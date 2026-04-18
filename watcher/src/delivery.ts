/**
 * Outbound webhook delivery for self-host — one-shot.
 *
 * After the watcher appends a journal entry for a new email, the deliverer
 * builds an `EmailReceivedEvent` via the SDK, signs it, and POSTs it once
 * to the operator's configured URL. The outcome (success or failure) is
 * appended to `deliveries.jsonl`.
 *
 * Why no retries? The journal is the source of truth. If a delivery fails
 * (receiver unreachable, 5xx, 4xx), the operator sees both the email in
 * `emails.jsonl` and the failure in `deliveries.jsonl` and can re-post
 * manually or tail the journal to recover. Self-host's ethos is "hand
 * the operator the primitives; trust them with the policy."
 *
 * Redirects are never followed (`redirect: "manual"`). Any 3xx is logged
 * as a failure — the operator should point `EVENT_WEBHOOK_URL` at the
 * final destination.
 */

import { createHash } from "node:crypto";
import { appendFile, readFile, stat } from "node:fs/promises";
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

/** Token audience strings — these MUST match what the download server verifies. */
export const AUDIENCE_RAW = "primitive:raw-download";
export const AUDIENCE_ATTACHMENTS = "primitive:attachments-download";

/** How long a download token is valid for. */
const DOWNLOAD_TOKEN_TTL_SECONDS = 15 * 60;

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
}

export interface DeliveryOutcome {
	status: "delivered" | "failed" | "skipped";
	confirmed: boolean;
	lastError: string | null;
	statusCode: number | null;
}

/** One line appended to `deliveries.jsonl` per delivery attempt. */
interface DeliveryLogEntry {
	seq: number;
	id: string;
	domain: string;
	url_hash: string;
	status: DeliveryOutcome["status"];
	confirmed?: boolean;
	status_code: number | null;
	last_error: string | null;
	at: string;
}

/**
 * Build the signed payload for the POST.
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
 * Hash the (configured URL) down to a short fingerprint suitable for
 * delivery logs. We log the hash, not the URL, so operators can grep logs
 * without re-emitting the full URL (which carries the signed token in the
 * download-URL case, and is redundant in the webhook-URL case).
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
}): Promise<EmailReceivedEvent> {
	const { canonicalJsonPath, emlPath, config } = params;

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
		attemptCount: 1,
	});
}

/**
 * Map the canonical JSON's snake_case auth block (as written by the
 * watcher) into the SDK schema's camelCase `EmailAuth` shape.
 *
 * Fill defaults when the watcher didn't supply a field — self-host auth
 * from the milter is best-effort today. `dmarcDkimAligned` is derived
 * from the per-signature `aligned` flags; `dmarcSpfAligned` and the
 * Strict flags need data the milter doesn't expose yet.
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
		dmarcDkimAligned: dkimSignatures.some((s) => s.aligned),
		dmarcSpfStrict: false,
		dmarcDkimStrict: false,
		dkimSignatures,
	};
}

/**
 * Append one line to `deliveries.jsonl`. No rotation — operators rotate
 * their own logs. Errors are logged and swallowed; a log-write failure
 * shouldn't itself crash the deliverer.
 */
async function appendDeliveryLog(
	path: string,
	entry: DeliveryLogEntry,
): Promise<void> {
	try {
		await appendFile(path, `${JSON.stringify(entry)}\n`);
	} catch (err) {
		console.error(`[delivery-log] failed to append: ${err}`);
	}
}

/**
 * One-shot delivery: build, sign, POST, log. Never throws — the caller
 * doesn't care which way it went.
 */
export async function deliverEvent(
	input: DeliverEventInput,
): Promise<DeliveryOutcome> {
	const fetchImpl = input.fetchImpl ?? fetch;
	const now = input.now ?? (() => Date.now());
	const urlHash = hashUrl(input.config.webhookUrl);

	const logAndReturn = async (
		outcome: DeliveryOutcome,
	): Promise<DeliveryOutcome> => {
		await appendDeliveryLog(input.deliveriesJsonlPath, {
			seq: input.seq,
			id: input.id,
			domain: input.domain,
			url_hash: urlHash,
			status: outcome.status,
			confirmed: outcome.confirmed,
			status_code: outcome.statusCode,
			last_error: outcome.lastError,
			at: new Date(now()).toISOString(),
		});
		return outcome;
	};

	// Pre-flight: the download server can only serve what's on disk. If the
	// .eml is missing we skip the POST entirely — the receiver's download.url
	// would 404 anyway.
	const emlStat = await stat(input.emlPath).catch(() => null);
	if (!emlStat) {
		return logAndReturn({
			status: "skipped",
			confirmed: false,
			statusCode: null,
			lastError: `raw .eml missing: ${input.emlPath}`,
		});
	}

	let event: EmailReceivedEvent;
	try {
		event = await buildEventFromFiles({
			canonicalJsonPath: input.canonicalJsonPath,
			emlPath: input.emlPath,
			config: input.config,
		});
	} catch (err) {
		return logAndReturn({
			status: "failed",
			confirmed: false,
			statusCode: null,
			lastError: `build event failed: ${err instanceof Error ? err.message : String(err)}`,
		});
	}

	const timestampSeconds = Math.floor(now() / 1000);
	const { rawBody, signatureHeader } = buildSignedPayload({
		event,
		secret: input.config.webhookSecret,
		timestampSeconds,
	});

	try {
		const response = await fetchImpl(input.config.webhookUrl, {
			method: "POST",
			redirect: "manual",
			signal: AbortSignal.timeout(input.config.timeoutMs),
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

		const delivered = response.status >= 200 && response.status < 300;
		const confirmed =
			response.headers.get("primitive-confirmed") === "true" ||
			response.headers.get("mymx-confirmed") === "true";

		return logAndReturn({
			status: delivered ? "delivered" : "failed",
			confirmed,
			statusCode: response.status,
			lastError: delivered ? null : `HTTP ${response.status}`,
		});
	} catch (err) {
		return logAndReturn({
			status: "failed",
			confirmed: false,
			statusCode: null,
			lastError: `fetch failed: ${err instanceof Error ? err.message : String(err)}`,
		});
	}
}
