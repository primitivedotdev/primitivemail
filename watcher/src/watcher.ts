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

import {
	bundleAttachments,
	parseEmailWithAttachments,
	toCanonicalHeaders,
	toParsedDataComplete,
} from "@primitivedotdev/sdk/parser";

const MAIL_DIR = process.env.MAIL_DIR ?? "/mail/incoming";
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS ?? "1000");
const HEARTBEAT_PATH = "/tmp/watcher-heartbeat";
const BATCH_LIMIT = Number(process.env.BATCH_LIMIT ?? "50");
const JOURNAL_PATH = join(MAIL_DIR, "emails.jsonl");

let shuttingDown = false;
let processing = false;
let nextSeq = 1;

/**
 * Extract bare email address from RFC 5322 format.
 * "Jane Doe" <jane@example.com> → jane@example.com
 */
function extractAddress(from: string | null): string | null {
	if (!from) return null;
	const match = from.match(/<([^>]+)>/);
	return match ? match[1] : from;
}

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

/**
 * Build the canonical auth object from .meta.json auth data.
 * Maps the milter's flat dkim/dkim_domains into the richer dkim_signatures array.
 */
function buildAuth(auth: MetaJson["auth"]) {
	const result: Record<string, unknown> = {
		spf: auth.spf,
	};

	// Build dkim_signatures array from milter's flat data
	if (auth.dkim !== undefined && auth.dkim_domains) {
		result.dkim_signatures = auth.dkim_domains.map((domain) => ({
			domain,
			result: auth.dkim,
			// Aligned if the DKIM domain matches the DMARC from_domain
			aligned: auth.dmarc_from_domain
				? domain.toLowerCase() === auth.dmarc_from_domain.toLowerCase()
				: false,
		}));
	}

	if (auth.dmarc !== undefined) {
		result.dmarc = auth.dmarc;
		result.dmarc_policy = auth.dmarc_policy ?? null;
		result.dmarc_from_domain = auth.dmarc_from_domain ?? null;
	}

	return result;
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

	// Bundle attachments if any are downloadable
	const downloadable = parsed.attachments.filter((a) => a.isDownloadable);
	let attachmentsDownloadUrl: string | null = null;

	if (downloadable.length > 0) {
		const bundle = await bundleAttachments(downloadable);
		if (!bundle) throw new Error("Failed to bundle attachments");
		// Atomic write: tmp then rename
		const tarTmpPath = `${tarGzPath}.tmp`;
		await writeFile(tarTmpPath, bundle.tarGzBuffer);
		await rename(tarTmpPath, tarGzPath);
		attachmentsDownloadUrl = `${domainDir}/${base}.attachments.tar.gz`;
		console.log(`  Bundled ${downloadable.length} attachments -> ${tarGzPath}`);
	}

	// Map parser output to canonical format using SDK mapping functions
	const headers = toCanonicalHeaders(parsed);
	const parsedData = toParsedDataComplete(parsed, attachmentsDownloadUrl);

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
		auth: buildAuth(meta.auth),
	};

	// Atomic write: .tmp then rename
	const tmpPath = `${jsonPath}.tmp`;
	await writeFile(tmpPath, JSON.stringify(canonical, null, 2));
	await rename(tmpPath, jsonPath);

	// Append to journal
	const journalEntry = {
		seq: nextSeq++,
		id: canonical.id,
		received_at: canonical.received_at,
		domain: domainDir,
		from: canonical.headers.from,
		from_address: extractAddress(canonical.headers.from),
		to: canonical.headers.to,
		subject: canonical.headers.subject,
		path: `${domainDir}/${base}.json`,
		attachment_count: parsed.attachments.filter((a) => a.isDownloadable).length,
	};
	await appendFile(JOURNAL_PATH, `${JSON.stringify(journalEntry)}\n`);

	console.log(`  Wrote ${jsonPath}`);
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

// Graceful shutdown: let current processing finish, then exit
for (const signal of ["SIGTERM", "SIGINT"] as const) {
	process.on(signal, () => {
		console.log(`Received ${signal}, shutting down gracefully...`);
		shuttingDown = true;
		if (!processing) process.exit(0);
	});
}

// Poll loop using setTimeout to prevent overlapping cycles
async function loop() {
	if (shuttingDown) {
		process.exit(0);
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
		process.exit(0);
		return;
	}
	setTimeout(loop, POLL_INTERVAL_MS);
}

await loop();
