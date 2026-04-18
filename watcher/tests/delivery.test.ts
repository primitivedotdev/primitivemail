import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { handleWebhook } from "@primitivedotdev/sdk";
import type { EmailAuth } from "@primitivedotdev/sdk/contract";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DeliveryConfig } from "../src/config.js";
import { computeEndpointId } from "../src/config.js";
import { buildEventFromFiles, deliverEvent, hashUrl } from "../src/delivery.js";

/** Minimal-but-valid EmailAuth fixture for tests that don't care about auth. */
const TEST_AUTH: EmailAuth = {
	spf: "pass",
	dmarc: "pass",
	dmarcPolicy: "reject",
	dmarcFromDomain: "example.com",
	dmarcSpfAligned: false,
	dmarcDkimAligned: true,
	dmarcSpfStrict: false,
	dmarcDkimStrict: false,
	dkimSignatures: [
		{
			domain: "example.com",
			selector: null,
			result: "pass",
			aligned: true,
			keyBits: null,
			algo: null,
		},
	],
};

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures");

async function makeTmpEmailDir(): Promise<{
	dir: string;
	canonicalJsonPath: string;
	emlPath: string;
	id: string;
	domain: string;
}> {
	const dir = await mkdtemp(join(tmpdir(), "watcher-delivery-"));
	const domain = "example.com";
	const id = "20260417T120000Z-testtest";
	const domainDir = join(dir, domain);
	await mkdir(domainDir, { recursive: true });

	const canonicalJsonPath = join(domainDir, `${id}.json`);
	const emlPath = join(domainDir, `${id}.eml`);

	await writeFile(
		canonicalJsonPath,
		await readFile(join(FIXTURE_DIR, "sample.json")),
	);
	await writeFile(emlPath, await readFile(join(FIXTURE_DIR, "sample.eml")));

	return { dir, canonicalJsonPath, emlPath, id, domain };
}

function makeConfig(overrides: Partial<DeliveryConfig> = {}): DeliveryConfig {
	return {
		enabled: true,
		webhookUrl: "http://localhost:65535/hook",
		webhookSecret: "test-secret",
		timeoutMs: 5_000,
		downloadServerPort: 4001,
		downloadBaseUrl: "http://localhost:4001",
		endpointId: computeEndpointId("http://localhost:65535/hook", "test-secret"),
		...overrides,
	};
}

describe("hashUrl", () => {
	it("is stable and 16 hex chars", () => {
		const a = hashUrl("https://example.com/hook");
		const b = hashUrl("https://example.com/hook");
		expect(a).toBe(b);
		expect(a).toMatch(/^[0-9a-f]{16}$/);
	});
	it("differs across URLs", () => {
		expect(hashUrl("https://a.example.com/")).not.toBe(
			hashUrl("https://b.example.com/"),
		);
	});
});

describe("buildEventFromFiles", () => {
	it("produces a schema-valid event for the sample fixture", async () => {
		const { dir, canonicalJsonPath, emlPath } = await makeTmpEmailDir();
		try {
			const event = await buildEventFromFiles({
				canonicalJsonPath,
				emlPath,
				config: makeConfig(),
				auth: TEST_AUTH,
			});
			expect(event.event).toBe("email.received");
			expect(event.email.headers.message_id).toBe("<unit-test-1@example.com>");
			expect(event.email.smtp.rcpt_to).toEqual(["bob@example.com"]);
			expect(event.email.parsed.attachments_download_url).toBeNull();
			// Inline raw.data for small emails
			expect(event.email.content.raw.included).toBe(true);
			expect(event.email.content.download.url).toContain("/raw/");
			expect(event.email.content.download.url).toContain("token=");
			// The canonical JSON's `headers.date` must round-trip to the event.
			// Missing this field silently returns null to receivers.
			expect(event.email.headers.date).toBe("Fri, 17 Apr 2026 12:00:00 +0000");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});

describe("deliverEvent (fetch stubbed)", () => {
	let tmp: Awaited<ReturnType<typeof makeTmpEmailDir>>;
	let deliveriesJsonlPath: string;
	beforeEach(async () => {
		tmp = await makeTmpEmailDir();
		deliveriesJsonlPath = join(tmp.dir, "deliveries.jsonl");
	});
	afterEach(async () => {
		await rm(tmp.dir, { recursive: true, force: true });
	});

	it("delivers on 2xx and logs delivered status with confirmed flag", async () => {
		const fetchImpl = vi.fn(
			async () =>
				new Response("", {
					status: 200,
					headers: { "primitive-confirmed": "true" },
				}),
		);
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("delivered");
		expect(outcome.confirmed).toBe(true);
		expect(outcome.statusCode).toBe(200);

		const log = await readFile(deliveriesJsonlPath, "utf-8");
		const line = JSON.parse(log.trim());
		expect(line.status).toBe("delivered");
		expect(line.confirmed).toBe(true);
		expect(line.status_code).toBe(200);
	});

	it("does not set confirmed=true on a non-2xx response even if the header is present", async () => {
		// A reverse-proxy or partial-failure handler might echo the
		// `primitive-confirmed` header on a 5xx/4xx. The deliverer must
		// refuse to mark that as confirmed — the receiver hasn't actually
		// successfully processed anything.
		const fetchImpl = vi.fn(
			async () =>
				new Response("", {
					status: 500,
					headers: { "primitive-confirmed": "true" },
				}),
		);
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("failed");
		expect(outcome.confirmed).toBe(false);

		const log = await readFile(deliveriesJsonlPath, "utf-8");
		const line = JSON.parse(log.trim());
		expect(line.status).toBe("failed");
		expect(line.confirmed).toBe(false);
	});

	it("logs failed on 5xx — no retry", async () => {
		const fetchImpl = vi.fn(async () => new Response("", { status: 503 }));
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("failed");
		expect(outcome.statusCode).toBe(503);
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("logs failed on 4xx", async () => {
		const fetchImpl = vi.fn(async () => new Response("", { status: 400 }));
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("failed");
		expect(outcome.statusCode).toBe(400);
	});

	it("logs failed on 3xx — we don't follow redirects", async () => {
		const fetchImpl = vi.fn(
			async () =>
				new Response("", {
					status: 308,
					headers: { location: "https://new.example.com/hook" },
				}),
		);
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("failed");
		expect(outcome.statusCode).toBe(308);
	});

	it("calls fetch with redirect: manual", async () => {
		const fetchImpl = vi.fn(async () => new Response("", { status: 200 }));
		await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		const [, init] = fetchImpl.mock.calls[0] as unknown as [
			string,
			RequestInit,
		];
		expect(init.redirect).toBe("manual");
	});

	it("logs failed on network error", async () => {
		const fetchImpl = vi.fn(async () => {
			throw new Error("ECONNREFUSED");
		});
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("failed");
		expect(outcome.statusCode).toBeNull();
		expect(outcome.lastError).toMatch(/ECONNREFUSED/);
	});

	it("outputs a signature that handleWebhook can verify", async () => {
		const config = makeConfig();
		let capturedBody = "";
		let capturedHeaders: Record<string, string> = {};
		const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => {
			capturedBody = init.body as string;
			capturedHeaders = init.headers as Record<string, string>;
			return new Response("", { status: 200 });
		});
		const outcome = await deliverEvent({
			config,
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("delivered");
		const event = handleWebhook({
			body: capturedBody,
			headers: capturedHeaders,
			secret: config.webhookSecret,
		});
		expect(event.event).toBe("email.received");
		expect(event.email.id).toBe(tmp.id);
	});

	it("skips with missing-eml status when .eml is absent", async () => {
		await rm(tmp.emlPath);
		const fetchImpl = vi.fn(async () => new Response("", { status: 200 }));
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			auth: TEST_AUTH,
			fetchImpl: fetchImpl as unknown as typeof fetch,
		});
		expect(outcome.status).toBe("skipped");
		expect(fetchImpl).not.toHaveBeenCalled();
	});
});
