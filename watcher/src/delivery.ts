/**
 * Outbound webhook delivery for self-host.
 *
 * After the watcher durably appends a journal entry for a new email, the
 * deliverer constructs an `EmailReceivedEvent` (via the SDK, byte-identical
 * to the managed path), signs it with HMAC, and POSTs to the operator's
 * configured URL. On retryable failure it backs off exponentially up to
 * `maxAttempts`. On final outcome (success or exhaustion) it appends one
 * line to `deliveries.jsonl`, which rotates at 100 MB.
 *
 * Never follows redirects. User-controlled URLs should point at the final
 * destination; 3xx is treated as terminal (except 307, which we retry).
 */

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import {
	type EmailReceivedEvent,
	buildEventFromParsedData,
} from "@primitivedotdev/sdk/contract";
import {
	LEGACY_SIGNATURE_HEADER,
	PRIMITIVE_SIGNATURE_HEADER,
	generateDownloadToken,
	signWebhookPayload,
} from "@primitivedotdev/sdk/webhook";
import type { DeliveryConfig } from "./config.js";
import { appendDeliveryLog } from "./delivery-log.js";

/** Token audience strings — these MUST match what the download server verifies. */
export const AUDIENCE_RAW = "primitive:raw-download";
export const AUDIENCE_ATTACHMENTS = "primitive:attachments-download";

/** How long a download token is valid for. */
const DOWNLOAD_TOKEN_TTL_SECONDS = 15 * 60;

/** Backoff delays between attempts, in ms. Indexed by attempt number minus 1. */
const BACKOFF_SCHEDULE_MS = [
	1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000,
];

/** Cap honored on 429 Retry-After. */
const MAX_RETRY_AFTER_SECONDS = 5 * 60;

/**
 * Canonical JSON file shape as written by the watcher's email processor.
 * Only the fields the deliverer needs are listed; extra fields are ignored.
 */
export interface CanonicalJson {
	id: string;
	received_at: string;
	smtp: {
		helo: string | null;
		mail_from: string;
		rcpt_to: string[];
	};
	headers: {
		message_id: string | null;
		subject: string | null;
		from: string;
		to: string;
		date: string | null;
	};
	parsed: {
		status: "complete" | "failed";
		body_text: string | null;
		body_html: string | null;
		reply_to: Array<{ address: string; name: string | null }> | null;
		cc: Array<{ address: string; name: string | null }> | null;
		bcc: Array<{ address: string; name: string | null }> | null;
		in_reply_to: string[] | null;
		references: string[] | null;
		attachments: Array<{
			filename: string | null;
			content_type: string;
			size_bytes: number;
			sha256: string;
			part_index: number;
			tar_path: string;
		}>;
		attachments_download_url: string | null;
	};
	auth: Record<string, unknown>;
}

export interface DeliverEventInput {
	config: DeliveryConfig;
	canonicalJsonPath: string;
	emlPath: string;
	id: string;
	seq: number;
	domain: string;
	deliveriesJsonlPath: string;
	/** Optional for tests: inject a fetch implementation. */
	fetchImpl?: typeof fetch;
	/** Optional for tests: override current time (ms since epoch). */
	now?: () => number;
	/** Optional for tests: override sleep between retries. */
	sleep?: (ms: number) => Promise<void>;
}

export interface DeliveryOutcome {
	status:
		| "delivered"
		| "failed"
		| "abandoned-at-shutdown"
		| "skipped"
		| "redirect-endpoint-moved";
	confirmed: boolean;
	attempts: number;
	lastError: string | null;
	statusCode: number | null;
}

type AttemptResult =
	| { kind: "success"; statusCode: number; confirmed: boolean }
	| { kind: "permanent"; statusCode: number | null; error: string }
	| {
			kind: "retryable";
			statusCode: number | null;
			error: string;
			retryAfterMs?: number;
	  };

function defaultSleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function backoffFor(attempt: number): number {
	const idx = Math.max(
		0,
		Math.min(attempt - 1, BACKOFF_SCHEDULE_MS.length - 1),
	);
	return BACKOFF_SCHEDULE_MS[idx];
}

/**
 * Parse Retry-After header (either seconds or HTTP date) into a delay in ms.
 * Returns null if absent or unparseable.
 */
export function parseRetryAfterMs(
	header: string | null,
	now: number,
): number | null {
	if (!header) return null;
	const seconds = Number.parseInt(header, 10);
	if (Number.isFinite(seconds) && String(seconds) === header.trim()) {
		const bounded = Math.max(0, Math.min(seconds, MAX_RETRY_AFTER_SECONDS));
		return bounded * 1000;
	}
	const date = Date.parse(header);
	if (!Number.isNaN(date)) {
		const delta = Math.max(0, date - now);
		return Math.min(delta, MAX_RETRY_AFTER_SECONDS * 1000);
	}
	return null;
}

/**
 * Classify an HTTP response into success/retryable/permanent.
 * Pure function — doesn't touch the body.
 */
export function classifyResponse(
	response: { status: number; headers: { get(name: string): string | null } },
	now: number,
): AttemptResult {
	const { status } = response;

	if (status >= 200 && status < 300) {
		const confirmed =
			response.headers.get("primitive-confirmed") === "true" ||
			response.headers.get("mymx-confirmed") === "true";
		return { kind: "success", statusCode: status, confirmed };
	}

	// 3xx — treat redirect responses as terminal. 307 (Temporary Redirect)
	// retries against the same URL; everything else is permanent because we
	// refuse to chase user-controlled destinations.
	if (status >= 300 && status < 400) {
		if (status === 307) {
			return { kind: "retryable", statusCode: status, error: `HTTP ${status}` };
		}
		return {
			kind: "permanent",
			statusCode: status,
			error: `HTTP ${status} — endpoint moved; reconfigure URL`,
		};
	}

	if (status === 429) {
		const retryAfterMs = parseRetryAfterMs(
			response.headers.get("retry-after"),
			now,
		);
		return {
			kind: "retryable",
			statusCode: status,
			error: `HTTP ${status}`,
			retryAfterMs: retryAfterMs ?? undefined,
		};
	}

	if (status >= 400 && status < 500) {
		return { kind: "permanent", statusCode: status, error: `HTTP ${status}` };
	}

	return { kind: "retryable", statusCode: status, error: `HTTP ${status}` };
}

/**
 * Build the signed, retryable event payload for a specific attempt.
 * Timestamp is fresh per-attempt so the receiver's tolerance window always
 * sees a recent signature even after backoff delays.
 */
export function buildSignedPayload(params: {
	event: EmailReceivedEvent;
	secret: string;
	timestampSeconds: number;
}): { rawBody: string; signatureHeader: string } {
	const attempted_at = new Date(params.timestampSeconds * 1000).toISOString();
	const payload = {
		...params.event,
		delivery: { ...params.event.delivery, attempted_at },
	};
	const rawBody = JSON.stringify(payload);
	const { header } = signWebhookPayload(
		rawBody,
		params.secret,
		params.timestampSeconds,
	);
	return { rawBody, signatureHeader: header };
}

/**
 * Hash the (configured URL) down to a short fingerprint suitable for delivery
 * logs. We log the hash, not the URL, so operators can grep logs without
 * re-emitting the URL everywhere.
 */
export function hashUrl(url: string): string {
	return createHash("sha256").update(url).digest("hex").slice(0, 16);
}

/**
 * Read the canonical JSON + raw .eml, hand them to the SDK helper, and
 * return a schema-valid event ready for signing.
 */
export async function buildEventFromFiles(params: {
	canonicalJsonPath: string;
	emlPath: string;
	config: DeliveryConfig;
	attemptCount: number;
}): Promise<EmailReceivedEvent> {
	const { canonicalJsonPath, emlPath, config, attemptCount } = params;

	const [canonicalText, rawBytes] = await Promise.all([
		readFile(canonicalJsonPath, "utf-8"),
		readFile(emlPath),
	]);
	const canonical = JSON.parse(canonicalText) as CanonicalJson;

	if (canonical.parsed.status !== "complete") {
		throw new Error(
			`Cannot deliver event for ${canonical.id}: parsed.status is ${canonical.parsed.status}`,
		);
	}

	const downloadExpiresSeconds =
		Math.floor(Date.now() / 1000) + DOWNLOAD_TOKEN_TTL_SECONDS;
	const downloadExpiresAt = new Date(
		downloadExpiresSeconds * 1000,
	).toISOString();

	const rawToken = generateDownloadToken({
		emailId: canonical.id,
		expiresAt: downloadExpiresSeconds,
		audience: AUDIENCE_RAW,
		secret: config.webhookSecret,
	});
	const downloadUrl = `${config.downloadBaseUrl}/raw/${encodeURIComponent(canonical.id)}?token=${rawToken}`;

	let attachmentsDownloadUrl: string | null = null;
	if (canonical.parsed.attachments.length > 0) {
		const attToken = generateDownloadToken({
			emailId: canonical.id,
			expiresAt: downloadExpiresSeconds,
			audience: AUDIENCE_ATTACHMENTS,
			secret: config.webhookSecret,
		});
		attachmentsDownloadUrl = `${config.downloadBaseUrl}/attachments/${encodeURIComponent(canonical.id)}?token=${attToken}`;
	}

	return buildEventFromParsedData({
		emailId: canonical.id,
		endpointId: config.endpointId,
		rawBytes,
		parsed: {
			status: "complete",
			error: null,
			body_text: canonical.parsed.body_text,
			body_html: canonical.parsed.body_html,
			reply_to: canonical.parsed.reply_to,
			cc: canonical.parsed.cc,
			bcc: canonical.parsed.bcc,
			in_reply_to: canonical.parsed.in_reply_to,
			references: canonical.parsed.references,
			attachments: canonical.parsed.attachments,
			attachments_download_url: attachmentsDownloadUrl,
		},
		messageId: canonical.headers.message_id,
		sender: canonical.headers.from,
		recipient: canonical.headers.to,
		subject: canonical.headers.subject,
		receivedAt: canonical.received_at,
		smtpHelo: canonical.smtp.helo,
		smtpMailFrom: canonical.smtp.mail_from,
		smtpRcptTo: canonical.smtp.rcpt_to as [string, ...string[]],
		auth: authFromCanonical(canonical.auth),
		analysis: {},
		downloadUrl,
		downloadExpiresAt,
		attachmentsDownloadUrl,
		attemptCount,
	});
}

/**
 * Map the canonical JSON's snake_case auth block (as written by the watcher)
 * into the SDK schema's camelCase `EmailAuth` shape.
 *
 * We accept what we have and fill defaults for anything the watcher didn't
 * supply, rather than failing — self-host auth populated by the milter is
 * best-effort today.
 */
function authFromCanonical(auth: Record<string, unknown>): {
	spf:
		| "pass"
		| "fail"
		| "softfail"
		| "neutral"
		| "none"
		| "temperror"
		| "permerror";
	dmarc: "pass" | "fail" | "none" | "temperror" | "permerror";
	dmarcPolicy: "reject" | "quarantine" | "none" | null;
	dmarcFromDomain: string | null;
	dmarcSpfAligned: boolean;
	dmarcDkimAligned: boolean;
	dmarcSpfStrict: boolean;
	dmarcDkimStrict: boolean;
	dkimSignatures: Array<{
		domain: string;
		selector: string | null;
		result: "pass" | "fail" | "temperror" | "permerror";
		aligned: boolean;
		keyBits: number | null;
		algo: string | null;
	}>;
} {
	type Spf =
		| "pass"
		| "fail"
		| "softfail"
		| "neutral"
		| "none"
		| "temperror"
		| "permerror";
	type Dmarc = "pass" | "fail" | "none" | "temperror" | "permerror";
	type DmarcPolicy = "reject" | "quarantine" | "none";
	type DkimRes = "pass" | "fail" | "temperror" | "permerror";

	const spfRaw = typeof auth.spf === "string" ? auth.spf.toLowerCase() : "none";
	const spfValid: Spf[] = [
		"pass",
		"fail",
		"softfail",
		"neutral",
		"none",
		"temperror",
		"permerror",
	];
	const spf: Spf = (spfValid as string[]).includes(spfRaw)
		? (spfRaw as Spf)
		: "none";

	const dmarcRaw =
		typeof auth.dmarc === "string" ? auth.dmarc.toLowerCase() : "none";
	const dmarcValid: Dmarc[] = [
		"pass",
		"fail",
		"none",
		"temperror",
		"permerror",
	];
	const dmarc: Dmarc = (dmarcValid as string[]).includes(dmarcRaw)
		? (dmarcRaw as Dmarc)
		: "none";

	const policyRaw =
		typeof auth.dmarc_policy === "string"
			? auth.dmarc_policy.toLowerCase()
			: null;
	const policyValid: DmarcPolicy[] = ["reject", "quarantine", "none"];
	const dmarcPolicy: DmarcPolicy | null =
		policyRaw && (policyValid as string[]).includes(policyRaw)
			? (policyRaw as DmarcPolicy)
			: null;

	const dmarcFromDomain =
		typeof auth.dmarc_from_domain === "string" ? auth.dmarc_from_domain : null;

	const rawSigs = Array.isArray(auth.dkim_signatures)
		? auth.dkim_signatures
		: [];
	const dkimValid: DkimRes[] = ["pass", "fail", "temperror", "permerror"];
	const dkimSignatures = rawSigs
		.map(
			(
				entry,
			):
				| ReturnType<typeof authFromCanonical>["dkimSignatures"][number]
				| null => {
				if (!entry || typeof entry !== "object") return null;
				const e = entry as Record<string, unknown>;
				const domain = typeof e.domain === "string" ? e.domain : null;
				if (!domain) return null;
				const resultRaw =
					typeof e.result === "string" ? e.result.toLowerCase() : "permerror";
				const result: DkimRes = (dkimValid as string[]).includes(resultRaw)
					? (resultRaw as DkimRes)
					: "permerror";
				return {
					domain,
					selector: typeof e.selector === "string" ? e.selector : null,
					result,
					aligned: e.aligned === true,
					keyBits: typeof e.keyBits === "number" ? e.keyBits : null,
					algo: typeof e.algo === "string" ? e.algo : null,
				};
			},
		)
		.filter((s): s is NonNullable<typeof s> => s !== null);

	return {
		spf,
		dmarc,
		dmarcPolicy,
		dmarcFromDomain,
		dmarcSpfAligned: false,
		dmarcDkimAligned: false,
		dmarcSpfStrict: false,
		dmarcDkimStrict: false,
		dkimSignatures,
	};
}

/**
 * Perform one signed POST attempt. Returns a classified result.
 * Wraps fetch in try/catch to convert network errors into `retryable`.
 */
export async function attemptOnce(params: {
	event: EmailReceivedEvent;
	config: DeliveryConfig;
	timestampSeconds: number;
	fetchImpl: typeof fetch;
	now: number;
}): Promise<AttemptResult> {
	const { event, config, timestampSeconds, fetchImpl, now } = params;
	const { rawBody, signatureHeader } = buildSignedPayload({
		event,
		secret: config.webhookSecret,
		timestampSeconds,
	});

	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), config.timeoutMs);
	try {
		const response = await fetchImpl(config.webhookUrl, {
			method: "POST",
			redirect: "manual",
			signal: controller.signal,
			headers: {
				"Content-Type": "application/json",
				"User-Agent": "primitive-webhooks/1",
				"X-Webhook-Event": "email.received",
				"X-Webhook-Id": event.id,
				[PRIMITIVE_SIGNATURE_HEADER]: signatureHeader,
				[LEGACY_SIGNATURE_HEADER]: signatureHeader,
			},
			body: rawBody,
		});
		return classifyResponse(response, now);
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		return {
			kind: "retryable",
			statusCode: null,
			error: `fetch failed: ${msg}`,
		};
	} finally {
		clearTimeout(timer);
	}
}

/**
 * Run the full delivery loop for one email: build event, attempt, backoff,
 * log outcome. Never throws — the caller doesn't care which way it went.
 */
export async function deliverEvent(
	input: DeliverEventInput,
): Promise<DeliveryOutcome> {
	const fetchImpl = input.fetchImpl ?? fetch;
	const now = input.now ?? (() => Date.now());
	const sleep = input.sleep ?? defaultSleep;

	// Pre-flight: ensure the files the download server will serve exist.
	// If the raw .eml is missing we can't build a valid event anyway.
	const emlStat = await stat(input.emlPath).catch(() => null);
	if (!emlStat) {
		const outcome: DeliveryOutcome = {
			status: "skipped",
			confirmed: false,
			attempts: 0,
			lastError: `raw .eml missing: ${input.emlPath}`,
			statusCode: null,
		};
		await appendDeliveryLog(input.deliveriesJsonlPath, {
			seq: input.seq,
			id: input.id,
			domain: input.domain,
			url_hash: hashUrl(input.config.webhookUrl),
			attempts: 0,
			status: outcome.status,
			last_error: outcome.lastError,
			last_attempt_at: new Date(now()).toISOString(),
		});
		return outcome;
	}

	let lastError: string | null = null;
	let lastStatusCode: number | null = null;
	let attempt = 0;
	const startedAt = now();

	while (attempt < input.config.maxAttempts) {
		attempt += 1;
		const event = await buildEventFromFiles({
			canonicalJsonPath: input.canonicalJsonPath,
			emlPath: input.emlPath,
			config: input.config,
			attemptCount: attempt,
		});

		const timestampSeconds = Math.floor(now() / 1000);
		const result = await attemptOnce({
			event,
			config: input.config,
			timestampSeconds,
			fetchImpl,
			now: now(),
		});

		if (result.kind === "success") {
			const outcome: DeliveryOutcome = {
				status: "delivered",
				confirmed: result.confirmed,
				attempts: attempt,
				lastError: null,
				statusCode: result.statusCode,
			};
			await appendDeliveryLog(input.deliveriesJsonlPath, {
				seq: input.seq,
				id: input.id,
				domain: input.domain,
				url_hash: hashUrl(input.config.webhookUrl),
				attempts: attempt,
				status: outcome.status,
				confirmed: outcome.confirmed,
				status_code: result.statusCode,
				last_attempt_at: new Date(now()).toISOString(),
				duration_ms: now() - startedAt,
			});
			return outcome;
		}

		lastError = result.error;
		lastStatusCode = result.statusCode;

		if (result.kind === "permanent") {
			const status =
				result.statusCode && result.statusCode >= 300 && result.statusCode < 400
					? "redirect-endpoint-moved"
					: "failed";
			const outcome: DeliveryOutcome = {
				status,
				confirmed: false,
				attempts: attempt,
				lastError: result.error,
				statusCode: result.statusCode,
			};
			await appendDeliveryLog(input.deliveriesJsonlPath, {
				seq: input.seq,
				id: input.id,
				domain: input.domain,
				url_hash: hashUrl(input.config.webhookUrl),
				attempts: attempt,
				status: outcome.status,
				last_error: outcome.lastError,
				status_code: result.statusCode,
				last_attempt_at: new Date(now()).toISOString(),
			});
			return outcome;
		}

		// retryable — sleep before next attempt unless we're out of budget
		if (attempt < input.config.maxAttempts) {
			const delay = result.retryAfterMs ?? backoffFor(attempt);
			await sleep(delay);
		}
	}

	const outcome: DeliveryOutcome = {
		status: "failed",
		confirmed: false,
		attempts: attempt,
		lastError,
		statusCode: lastStatusCode,
	};
	await appendDeliveryLog(input.deliveriesJsonlPath, {
		seq: input.seq,
		id: input.id,
		domain: input.domain,
		url_hash: hashUrl(input.config.webhookUrl),
		attempts: attempt,
		status: outcome.status,
		last_error: outcome.lastError,
		status_code: lastStatusCode,
		last_attempt_at: new Date(now()).toISOString(),
	});
	return outcome;
}

/**
 * For use by watchers draining in-flight deliveries on SIGTERM: produces a
 * stream of bytes for a given `.eml` file, for callers that want a Node
 * Readable for HTTP responses. Convenience wrapper.
 */
export function openRawStream(
	emlPath: string,
): ReturnType<typeof createReadStream> {
	return createReadStream(emlPath);
}
