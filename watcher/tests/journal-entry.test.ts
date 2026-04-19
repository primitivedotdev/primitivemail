import { describe, expect, it } from "vitest";
import { buildJournalEntry } from "../src/journal.js";

const baseCanonical = {
	id: "20260312T203149Z-14f065f1",
	received_at: "2026-03-12T20:31:49Z",
	headers: {
		from: '"Jane" <jane@example.com>',
		to: "inbox@example.com",
		subject: "Hello",
	},
};

describe("buildJournalEntry", () => {
	it("emits empty attachment_names when no attachments", () => {
		const entry = buildJournalEntry({
			seq: 1,
			canonical: baseCanonical,
			attachments: [],
			domainDir: "example.com",
			base: "20260312T203149Z-14f065f1",
		});
		expect(entry.attachment_count).toBe(0);
		expect(entry.attachment_names).toEqual([]);
	});

	it("includes filenames of every downloadable attachment", () => {
		const entry = buildJournalEntry({
			seq: 7,
			canonical: baseCanonical,
			attachments: [
				{ filename: "report.pdf", isDownloadable: true },
				{ filename: "logo.png", isDownloadable: true },
			],
			domainDir: "example.com",
			base: "20260312T203149Z-14f065f1",
		});
		expect(entry.seq).toBe(7);
		expect(entry.attachment_count).toBe(2);
		expect(entry.attachment_names).toEqual(["report.pdf", "logo.png"]);
	});

	it("excludes non-downloadable attachments (inline images, etc.)", () => {
		// inline images attached via cid: references are parsed as attachments
		// but aren't downloadable. They should not bloat the journal.
		const entry = buildJournalEntry({
			seq: 2,
			canonical: baseCanonical,
			attachments: [
				{ filename: "report.pdf", isDownloadable: true },
				{ filename: "inline-signature.png", isDownloadable: false },
			],
			domainDir: "example.com",
			base: "20260312T203149Z-14f065f1",
		});
		expect(entry.attachment_count).toBe(1);
		expect(entry.attachment_names).toEqual(["report.pdf"]);
	});

	it("preserves attachment order as parsed (insertion order)", () => {
		// Agents that key on attachment position (first PDF, second image) need
		// a stable order. The parser emits attachments in MIME tree order; the
		// journal must preserve that.
		const entry = buildJournalEntry({
			seq: 3,
			canonical: baseCanonical,
			attachments: [
				{ filename: "c.pdf", isDownloadable: true },
				{ filename: "a.pdf", isDownloadable: true },
				{ filename: "b.pdf", isDownloadable: true },
			],
			domainDir: "example.com",
			base: "20260312T203149Z-14f065f1",
		});
		expect(entry.attachment_names).toEqual(["c.pdf", "a.pdf", "b.pdf"]);
	});

	it("carries the contract fields verbatim", () => {
		// Regression guard: a refactor of the builder shouldn't silently
		// drop a journal field. AGENTS.md and doc 08 both document the
		// exact shape.
		const entry = buildJournalEntry({
			seq: 42,
			canonical: baseCanonical,
			attachments: [],
			domainDir: "example.com",
			base: "20260312T203149Z-14f065f1",
		});
		expect(entry).toEqual({
			seq: 42,
			id: "20260312T203149Z-14f065f1",
			received_at: "2026-03-12T20:31:49Z",
			domain: "example.com",
			from: '"Jane" <jane@example.com>',
			from_address: "jane@example.com",
			to: "inbox@example.com",
			subject: "Hello",
			path: "example.com/20260312T203149Z-14f065f1.json",
			attachment_count: 0,
			attachment_names: [],
		});
	});

	it("preserves null filename from parser (malformed MIME part)", () => {
		// Parser can produce attachments with filename=null for malformed or
		// unusual MIME parts. attachment_count should still reflect reality
		// (this attachment was downloadable), but the name slot carries null
		// so readers can fall back to the full JSON for content_type/id.
		const entry = buildJournalEntry({
			seq: 9,
			canonical: baseCanonical,
			attachments: [
				{ filename: "report.pdf", isDownloadable: true },
				{ filename: null, isDownloadable: true },
			],
			domainDir: "example.com",
			base: "20260312T203149Z-14f065f1",
		});
		expect(entry.attachment_count).toBe(2);
		expect(entry.attachment_names).toEqual(["report.pdf", null]);
	});

	it("handles missing headers gracefully", () => {
		// Edge case: bounce messages or malformed email can lack headers.
		const entry = buildJournalEntry({
			seq: 4,
			canonical: {
				id: "abc",
				received_at: "2026-03-12T00:00:00Z",
				headers: { from: null, to: null, subject: null },
			},
			attachments: [],
			domainDir: "example.com",
			base: "abc",
		});
		expect(entry.from).toBeNull();
		expect(entry.from_address).toBeNull();
		expect(entry.to).toBeNull();
		expect(entry.subject).toBeNull();
	});
});
