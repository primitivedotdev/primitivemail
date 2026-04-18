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
	type EmailAuth,
	type EmailReceivedEvent,
	buildEventFromParsedData,
} from "@primitivedotdev/sdk/contract";
import {
	LEGACY_CONFIRMED_HEADER,
	LEGACY_SIGNATURE_HEADER,
	PRIMITIVE_CONFIRMED_HEADER,
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
	// The on-disk `auth` block is not declared here: delivery takes
	// auth in-memory from the watcher (see `DeliverEventInput.auth`)
	// and never reads this field from the canonical JSON.
}

export interface DeliverEventInput {
	config: DeliveryConfig;
	canonicalJsonPath: string;
	emlPath: string;
	/**
	 * EmailAuth built from the milter's `.meta.json` input. Passed in
	 * memory rather than re-derived from the canonical JSON's snake_case
	 * auth block so there's only one place in the watcher that maps
	 * milter → SDK auth.
	 */
	auth: EmailAuth;
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
 * return a schema-valid event ready for signing. Auth is passed in
 * memory from the caller (see `DeliverEventInput.auth`) rather than
 * re-parsed from the canonical JSON's snake_case serialization.
 */
export async function buildEventFromFiles(params: {
	canonicalJsonPath: string;
	emlPath: string;
	config: DeliveryConfig;
	auth: EmailAuth;
}): Promise<EmailReceivedEvent> {
	const { canonicalJsonPath, emlPath, config, auth } = params;

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
		dateHeader: canonical.headers.date,
		receivedAt: canonical.received_at,
		smtpHelo: canonical.smtp.helo,
		smtpMailFrom: canonical.smtp.mail_from,
		smtpRcptTo: canonical.smtp.rcpt_to as [string, ...string[]],
		auth,
		analysis: {},
		downloadUrl,
		downloadExpiresAt,
		attachmentsDownloadUrl,
		attemptCount: 1,
	});
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
			auth: input.auth,
		});
	} catch (err) {
		return logAndReturn({
			status: "failed",
			confirmed: false,
			statusCode: null,
			lastError: `build event failed: ${err instanceof Error ? err.message : String(err)}`,
		});
	}

	// Sign the event as-built. No re-stamp: with one-shot delivery there's
	// no backoff window that could age the signature, so the SDK's default
	// `Date.now()` timestamp is fine for the `t=` header.
	const rawBody = JSON.stringify(event);
	const { header: signatureHeader } = signWebhookPayload(
		rawBody,
		input.config.webhookSecret,
	);

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
		// Only honor the confirmed header on a successful delivery — a
		// non-2xx response that happens to echo `primitive-confirmed: true`
		// (reverse-proxy behavior, partial-failure handlers) must not
		// produce a contradictory `{status: "failed", confirmed: true}`.
		// Header names come from the SDK so they can't silently drift from
		// what managed Primitive emits.
		const confirmed =
			delivered &&
			(response.headers.get(PRIMITIVE_CONFIRMED_HEADER) === "true" ||
				response.headers.get(LEGACY_CONFIRMED_HEADER) === "true");

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
