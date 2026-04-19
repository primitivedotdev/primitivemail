/**
 * Pure helpers for building `emails.jsonl` journal entries. Kept separate
 * from watcher.ts so tests can import the builder without triggering the
 * top-level `await loop()` that starts the watcher.
 */

/** Extract bare email address from RFC 5322 format. */
export function extractAddress(from: string | null): string | null {
	if (!from) return null;
	const match = from.match(/<([^>]+)>/);
	return match ? match[1] : from;
}

/** Minimum attachment shape the journal builder needs. */
export interface JournalAttachmentSource {
	filename: string | null;
	isDownloadable: boolean;
}

/** Shape of the per-email canonical JSON fields the journal builder reads. */
export interface JournalCanonicalSource {
	id: string;
	received_at: string;
	headers: {
		from: string | null;
		to: string | null;
		subject: string | null;
	};
}

export interface JournalEntry {
	seq: number;
	id: string;
	received_at: string;
	domain: string;
	from: string | null;
	from_address: string | null;
	to: string | null;
	subject: string | null;
	path: string;
	attachment_count: number;
	// Parallel to attachment_count: one entry per downloadable attachment,
	// in MIME tree order. Null for attachments that lack a filename in the
	// MIME part (rare, typically malformed or inline content handled oddly).
	// Readers should treat null the same way they would a missing Content-
	// Disposition filename: fall back to id/content_type from the full JSON.
	attachment_names: (string | null)[];
}

/**
 * Build a journal entry for `emails.jsonl`. Pure: takes parsed attachments
 * and canonical fields, returns the line object.
 *
 * `attachment_names` is a flat list of filenames for downloadable
 * attachments, so routing agents can decide whether to load the full
 * per-email JSON without a second read. `attachment_count` stays for
 * agents that ignore the new field.
 */
export function buildJournalEntry(args: {
	seq: number;
	canonical: JournalCanonicalSource;
	attachments: ReadonlyArray<JournalAttachmentSource>;
	domainDir: string;
	base: string;
}): JournalEntry {
	const downloadable = args.attachments.filter((a) => a.isDownloadable);
	return {
		seq: args.seq,
		id: args.canonical.id,
		received_at: args.canonical.received_at,
		domain: args.domainDir,
		from: args.canonical.headers.from,
		from_address: extractAddress(args.canonical.headers.from),
		to: args.canonical.headers.to,
		subject: args.canonical.headers.subject,
		path: `${args.domainDir}/${args.base}.json`,
		attachment_count: downloadable.length,
		attachment_names: downloadable.map((a) => a.filename),
	};
}
