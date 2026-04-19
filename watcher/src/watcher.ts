import { createHash } from "node:crypto";
import {
	appendFile,
	readFile,
	readdir,
	rename,
	stat,
	writeFile,
} from "node:fs/promises";
import { basename, dirname, join } from "node:path";

import type { EmailAuth } from "@primitivedotdev/sdk/contract";
import {
	bundleAttachments,
	parseEmailWithAttachments,
	toCanonicalHeaders,
	toParsedDataComplete,
} from "@primitivedotdev/sdk/parser";

import { type LoadedDeliveryConfig, loadDeliveryConfig } from "./config.js";
import { deliverEvent } from "./delivery.js";
import {
	type StartedDownloadServer,
	startDownloadServer,
} from "./download-server.js";
import { buildJournalEntry } from "./journal.js";

const MAIL_DIR = process.env.MAIL_DIR ?? "/mail/incoming";
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS ?? "1000");
const HEARTBEAT_PATH = "/tmp/watcher-heartbeat";
const BATCH_LIMIT = Number(process.env.BATCH_LIMIT ?? "50");
const JOURNAL_PATH = join(MAIL_DIR, "emails.jsonl");
const DELIVERIES_PATH = join(MAIL_DIR, "deliveries.jsonl");
// Time to let in-flight deliveries finish naturally on SIGTERM before we
// exit. One-shot deliveries typically complete well under this; this is
// just politeness.
const SHUTDOWN_GRACE_MS = Number(process.env.SHUTDOWN_GRACE_MS ?? "3000");

let shuttingDown = false;
let processing = false;
let nextSeq = 1;

const inFlightDeliveries = new Set<Promise<void>>();
let deliveryConfig: LoadedDeliveryConfig = { enabled: false };
let downloadServer: StartedDownloadServer | null = null;


/**
 * Recover the next sequence number from the last line of the journal.
 */
async function recoverSeq(): Promise<number> {
	try {
		const content = await readFile(JOURNAL_PATH, "utf-8");
		const lines = content.trimEnd().split("\n");
		const lastLine = lines[lines.length - 1];
		if (lastLine) {
			const entry = JSON.parse(lastLine);
			if (typeof entry.seq === "number") return entry.seq + 1;
		}
	} catch {
		// Journal doesn't exist yet
	}
	return 1;
}

interface MetaJson {
	smtp: {
		helo: string | null;
		mail_from: string;
		rcpt_to: string[];
	};
	auth: {
		spf: string;
		dkim?: string;
		dkim_domains?: string[];
		dmarc?: string;
		dmarc_policy?: string;
		dmarc_from_domain?: string;
	};
}

/** Valid SPF results per the schema. Unknown values coerce to "none". */
const SPF_RESULTS = new Set([
	"pass",
	"fail",
	"softfail",
	"neutral",
	"none",
	"temperror",
	"permerror",
] as const);
type SpfResult = EmailAuth["spf"];

const DMARC_RESULTS = new Set([
	"pass",
	"fail",
	"none",
	"temperror",
	"permerror",
] as const);
type DmarcResult = EmailAuth["dmarc"];

const DMARC_POLICIES = new Set(["reject", "quarantine", "none"] as const);
type DmarcPolicy = NonNullable<EmailAuth["dmarcPolicy"]>;

const DKIM_RESULTS = new Set([
	"pass",
	"fail",
	"temperror",
	"permerror",
] as const);
type DkimResult = EmailAuth["dkimSignatures"][number]["result"];

/**
 * Map the milter's flat `.meta.json` auth fields into the SDK's `EmailAuth`
 * shape in a single pass. This is the one and only auth adapter — the
 * canonical JSON on disk stores a snake_case serialization of the SAME
 * `EmailAuth` object (written at `processEmail` time), not a separate
 * representation, so there's nothing downstream to re-translate.
 *
 * `dmarcSpfAligned` and the `Strict` flags require milter-side data that
 * isn't exposed today; they default to `false`. `dmarcDkimAligned` is
 * derived from the per-signature `aligned` flags (DMARC passes iff at
 * least one DKIM signature is aligned with the RFC5322.From domain).
 */
export function emailAuthFromMilter(auth: MetaJson["auth"]): EmailAuth {
	const spfRaw = typeof auth.spf === "string" ? auth.spf.toLowerCase() : "none";
	const spf: SpfResult = (SPF_RESULTS as Set<string>).has(spfRaw)
		? (spfRaw as SpfResult)
		: "none";

	const dmarcRaw =
		typeof auth.dmarc === "string" ? auth.dmarc.toLowerCase() : "none";
	const dmarc: DmarcResult = (DMARC_RESULTS as Set<string>).has(dmarcRaw)
		? (dmarcRaw as DmarcResult)
		: "none";

	const policyRaw = auth.dmarc_policy?.toLowerCase() ?? null;
	const dmarcPolicy: DmarcPolicy | null =
		policyRaw && (DMARC_POLICIES as Set<string>).has(policyRaw)
			? (policyRaw as DmarcPolicy)
			: null;

	const dmarcFromDomain = auth.dmarc_from_domain ?? null;

	const dkimRaw = auth.dkim?.toLowerCase();
	const dkimResult: DkimResult =
		dkimRaw && (DKIM_RESULTS as Set<string>).has(dkimRaw)
			? (dkimRaw as DkimResult)
			: "permerror";

	const dkimSignatures = (auth.dkim_domains ?? []).map((domain) => ({
		domain,
		selector: null,
		result: dkimResult,
		// DMARC DKIM alignment requires BOTH (a) the signing domain matches
		// the RFC5322.From domain AND (b) the signature itself verified.
		// A failed or erroring signature from an aligned domain MUST NOT be
		// reported as aligned — a receiver gating security decisions on
		// `dmarcDkimAligned` would otherwise see a false positive.
		aligned:
			dkimResult === "pass" &&
			!!dmarcFromDomain &&
			domain.toLowerCase() === dmarcFromDomain.toLowerCase(),
		keyBits: null,
		algo: null,
	}));

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
 * Serialize an `EmailAuth` object into the snake_case subset we write to
 * canonical JSON on disk. Kept minimal (only fields the milter populates)
 * so the on-disk shape is a stable debug-readable view, not a duplicate
 * of the full SDK type. External readers of `<id>.json` should continue
 * to rely on the managed webhook payload for the canonical auth shape.
 */
function canonicalAuth(auth: EmailAuth): Record<string, unknown> {
	return {
		spf: auth.spf,
		dmarc: auth.dmarc,
		dmarc_policy: auth.dmarcPolicy,
		dmarc_from_domain: auth.dmarcFromDomain,
		dkim_signatures: auth.dkimSignatures.map((s) => ({
			domain: s.domain,
			result: s.result,
			aligned: s.aligned,
		})),
	};
}

/**
 * Mark an email as failed by writing a .failed marker file.
 * Prevents infinite retry loops on malformed emails.
 */
async function markFailed(metaPath: string, error: unknown): Promise<void> {
	const failedPath = `${metaPath}.failed`;
	const message = error instanceof Error ? error.message : String(error);
	await writeFile(failedPath, message).catch(() => {});
}

/**
 * Process a single .meta.json file: parse the .eml, bundle attachments,
 * merge metadata, and write the canonical .json.
 */
async function processEmail(metaPath: string): Promise<void> {
	const dir = dirname(metaPath);
	const domainDir = basename(dir);
	const base = basename(metaPath, ".meta.json");
	const emlPath = join(dir, `${base}.eml`);
	const jsonPath = join(dir, `${base}.json`);
	const tarGzPath = join(dir, `${base}.attachments.tar.gz`);

	// Verify .eml exists before reading
	const emlStat = await stat(emlPath).catch(() => null);
	if (!emlStat) {
		throw new Error(`Missing .eml file: ${emlPath}`);
	}

	// Read inputs
	const [emlBuffer, metaText] = await Promise.all([
		readFile(emlPath),
		readFile(metaPath, "utf-8"),
	]);

	const meta: MetaJson = JSON.parse(metaText);

	// Parse the email using the SDK
	const parsed = await parseEmailWithAttachments(emlBuffer);

	// Bundle attachments if any are downloadable. The canonical JSON's
	// `attachments_download_url` is null on disk — the real URL is minted
	// at delivery time by the watcher's download server with a signed
	// token, and isn't knowable at canonical-write time. The tar.gz path
	// is determined entirely by the filename convention
	// (<domain>/<id>.attachments.tar.gz) if any external reader needs it.
	const downloadable = parsed.attachments.filter((a) => a.isDownloadable);
	const hasAttachments = downloadable.length > 0;

	if (hasAttachments) {
		const bundle = await bundleAttachments(downloadable);
		if (!bundle) throw new Error("Failed to bundle attachments");
		// Atomic write: tmp then rename
		const tarTmpPath = `${tarGzPath}.tmp`;
		await writeFile(tarTmpPath, bundle.tarGzBuffer);
		await rename(tarTmpPath, tarGzPath);
		console.log(`  Bundled ${downloadable.length} attachments -> ${tarGzPath}`);
	}

	// Map parser output to canonical format using SDK mapping functions
	const headers = toCanonicalHeaders(parsed);
	const parsedData = toParsedDataComplete(parsed, null);
	const auth = emailAuthFromMilter(meta.auth);

	// Compute content metadata
	const emlSha256 = createHash("sha256").update(emlBuffer).digest("hex");

	// Extract ID and timestamp from filename (20260311T225855Z-089ecb30)
	const id = base;
	const tsMatch = base.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z/);
	const receivedAt = tsMatch
		? `${tsMatch[1]}-${tsMatch[2]}-${tsMatch[3]}T${tsMatch[4]}:${tsMatch[5]}:${tsMatch[6]}Z`
		: emlStat.mtime.toISOString();

	// Build the canonical JSON
	const canonical = {
		id,
		received_at: receivedAt,
		smtp: meta.smtp,
		headers,
		parsed: parsedData,
		content: {
			raw_path: `${domainDir}/${base}.eml`,
			size_bytes: emlBuffer.length,
			sha256: emlSha256,
		},
		auth: canonicalAuth(auth),
	};

	// Atomic write: .tmp then rename
	const tmpPath = `${jsonPath}.tmp`;
	await writeFile(tmpPath, JSON.stringify(canonical, null, 2));
	await rename(tmpPath, jsonPath);

	// Append to journal. Built via the exported pure helper so its shape
	// is unit-testable without spinning a full watcher.
	const journalEntry = buildJournalEntry({
		seq: nextSeq++,
		canonical,
		attachments: parsed.attachments,
		domainDir,
		base,
	});
	await appendFile(JOURNAL_PATH, `${JSON.stringify(journalEntry)}\n`);

	console.log(`  Wrote ${jsonPath}`);

	// Fire and forget — delivery runs outside the scan loop. Tombstone
	// entries (future `type` field) are skipped preemptively; none exist yet.
	if (deliveryConfig.enabled) {
		const config = deliveryConfig;
		const promise = deliverEvent({
			config,
			canonicalJsonPath: jsonPath,
			emlPath,
			auth,
			id: canonical.id,
			seq: journalEntry.seq,
			domain: domainDir,
			deliveriesJsonlPath: DELIVERIES_PATH,
		})
			.catch((err) => {
				console.error(`  delivery error for ${canonical.id}: ${err}`);
			})
			.then(() => undefined);
		inFlightDeliveries.add(promise);
		promise.finally(() => {
			inFlightDeliveries.delete(promise);
		});
	}
}

/**
 * Scan all domain directories for .meta.json files without a corresponding .json.
 */
async function scanAndProcess(): Promise<number> {
	let entries: string[];
	try {
		entries = await readdir(MAIL_DIR);
	} catch {
		return 0; // maildata dir doesn't exist yet, that's fine
	}

	let processed = 0;

	for (const domainDir of entries) {
		if (shuttingDown || processed >= BATCH_LIMIT) return processed;

		const domainPath = join(MAIL_DIR, domainDir);
		const domainStat = await stat(domainPath).catch(() => null);
		if (!domainStat?.isDirectory()) continue;
		// Skip hidden directories (.processed, .failed)
		if (domainDir.startsWith(".")) continue;

		const files = await readdir(domainPath);
		const metaFiles = files.filter((f) => f.endsWith(".meta.json"));

		for (const metaFile of metaFiles) {
			if (shuttingDown || processed >= BATCH_LIMIT) return processed;

			const base = metaFile.replace(".meta.json", "");
			const hasJson = files.includes(`${base}.json`);
			const hasFailed = files.includes(`${metaFile}.failed`);

			if (!hasJson && !hasFailed) {
				const metaPath = join(domainPath, metaFile);
				console.log(`Processing: ${domainDir}/${base}`);
				try {
					await processEmail(metaPath);
				} catch (err) {
					console.error(`  FAILED: ${err}`);
					await markFailed(metaPath, err);
				}
				processed++;
				await writeFile(HEARTBEAT_PATH, Date.now().toString()).catch(() => {});
			}
		}
	}

	return processed;
}

// --- Main ---

// Recover sequence number from journal before starting
nextSeq = await recoverSeq();

console.log("PrimitiveMail Watcher starting");
console.log(`  Mail dir: ${MAIL_DIR}`);
console.log(`  Poll interval: ${POLL_INTERVAL_MS}ms`);
console.log(`  Journal seq: ${nextSeq}`);

try {
	deliveryConfig = loadDeliveryConfig(process.env);
} catch (err) {
	console.error(
		`Invalid delivery configuration: ${err instanceof Error ? err.message : String(err)}`,
	);
	process.exit(1);
}

if (deliveryConfig.enabled) {
	console.log(
		`  Delivery enabled: endpointId=${deliveryConfig.endpointId} timeoutMs=${deliveryConfig.timeoutMs}`,
	);
	console.log(
		`  Download server: port=${deliveryConfig.downloadServerPort} baseUrl=${deliveryConfig.downloadBaseUrl}`,
	);
	downloadServer = await startDownloadServer({
		port: deliveryConfig.downloadServerPort,
		secret: deliveryConfig.webhookSecret,
		mailDir: MAIL_DIR,
	});

	// Cross-check: the configured base URL's port should match the port
	// the server actually listens on. Mismatches are a silent misconfig —
	// the watcher binds one port and embeds URLs pointing at another, so
	// every download URL 404s at the receiver. Warn loudly at startup;
	// don't fail, since an operator may intentionally route via proxy.
	try {
		const parsedBase = new URL(deliveryConfig.downloadBaseUrl);
		// `URL.port` is empty string when the URL uses the protocol's default
		// port (80 for http, 443 for https). Resolve the effective port so an
		// operator who set `DOWNLOAD_BASE_URL=http://host` (implicit port 80)
		// with `DOWNLOAD_SERVER_PORT=4001` still gets warned about the mismatch.
		const basePort =
			parsedBase.port || (parsedBase.protocol === "https:" ? "443" : "80");
		const expectedPort = String(deliveryConfig.downloadServerPort);
		if (basePort !== expectedPort) {
			console.warn(
				`  WARNING: DOWNLOAD_BASE_URL port (${basePort}) differs from DOWNLOAD_SERVER_PORT (${expectedPort}). If no reverse proxy is rewriting, download URLs in webhooks will be unreachable.`,
			);
		}
	} catch {
		// URL already validated at config load; swallow.
	}
} else {
	console.log("  Delivery disabled (EVENT_WEBHOOK_URL not set)");
}

let shutdownStarted = false;
async function shutdownAndExit(code: number): Promise<never> {
	// Re-entry guard: SIGTERM + SIGINT arriving together, or the poll loop
	// detecting `shuttingDown` at the same moment a signal handler fires,
	// could otherwise invoke this twice. Second caller hangs until the
	// first one's `process.exit` tears the event loop down.
	if (shutdownStarted) {
		await new Promise<never>(() => {});
		throw new Error("unreachable");
	}
	shutdownStarted = true;

	// One-shot deliveries usually finish in well under SHUTDOWN_GRACE_MS.
	// If any are still in-flight after the grace period we exit anyway —
	// the journal entry persists, so the operator can re-post manually.
	if (inFlightDeliveries.size > 0) {
		await Promise.race([
			Promise.all(inFlightDeliveries),
			new Promise((resolve) => setTimeout(resolve, SHUTDOWN_GRACE_MS)),
		]);
	}
	if (downloadServer) {
		await downloadServer.close().catch(() => {});
	}
	process.exit(code);
}

// Graceful shutdown: let current processing finish, drain deliveries, then exit.
for (const signal of ["SIGTERM", "SIGINT"] as const) {
	process.on(signal, () => {
		console.log(`Received ${signal}, shutting down gracefully...`);
		shuttingDown = true;
		if (!processing) {
			void shutdownAndExit(0);
		}
	});
}

// Poll loop using setTimeout to prevent overlapping cycles
async function loop() {
	if (shuttingDown) {
		await shutdownAndExit(0);
		return;
	}
	processing = true;
	try {
		await scanAndProcess();
	} catch (err) {
		console.error(`Poll error: ${err}`);
	}
	await writeFile(HEARTBEAT_PATH, Date.now().toString()).catch(() => {});
	processing = false;
	if (shuttingDown) {
		await shutdownAndExit(0);
		return;
	}
	setTimeout(loop, POLL_INTERVAL_MS);
}

await loop();
