import {
	mkdir,
	mkdtemp,
	readFile,
	rm,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleWebhook } from "@primitivedotdev/sdk";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DeliveryConfig } from "../src/config.js";
import { computeEndpointId } from "../src/config.js";
import {
	DELIVERY_LOG_SOFT_CAP_BYTES,
	__resetRotationCounterForTests,
	maybeRotate,
} from "../src/delivery-log.js";
import {
	buildEventFromFiles,
	classifyResponse,
	deliverEvent,
	hashUrl,
	parseRetryAfterMs,
} from "../src/delivery.js";

const FIXTURE_DIR = join(__dirname, "fixtures");

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
		maxAttempts: 3,
		timeoutMs: 5_000,
		downloadServerPort: 4001,
		downloadBaseUrl: "http://localhost:4001",
		endpointId: computeEndpointId("http://localhost:65535/hook", "test-secret"),
		...overrides,
	};
}

describe("parseRetryAfterMs", () => {
	it("parses integer seconds", () => {
		expect(parseRetryAfterMs("30", Date.now())).toBe(30_000);
	});

	it("caps very large values at 5 minutes", () => {
		expect(parseRetryAfterMs("3600", Date.now())).toBe(5 * 60 * 1000);
	});

	it("parses HTTP date and returns delta", () => {
		const now = 1_700_000_000_000;
		const future = new Date(now + 45_000).toUTCString();
		const result = parseRetryAfterMs(future, now);
		expect(result).toBeGreaterThanOrEqual(44_000);
		expect(result).toBeLessThanOrEqual(46_000);
	});

	it("returns null for garbage", () => {
		expect(parseRetryAfterMs("nope", Date.now())).toBeNull();
	});

	it("returns null for missing header", () => {
		expect(parseRetryAfterMs(null, Date.now())).toBeNull();
	});
});

describe("classifyResponse", () => {
	const mkResponse = (
		status: number,
		headers: Record<string, string> = {},
	) => ({
		status,
		headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
	});

	it("treats 2xx as success with confirmed flag detection", () => {
		const res = classifyResponse(mkResponse(200), Date.now());
		expect(res.kind).toBe("success");
	});

	it("flags primitive-confirmed", () => {
		const res = classifyResponse(
			mkResponse(200, { "primitive-confirmed": "true" }),
			Date.now(),
		);
		expect(res.kind).toBe("success");
		if (res.kind === "success") expect(res.confirmed).toBe(true);
	});

	it.each([301, 302, 303, 308])("treats %i as permanent redirect", (status) => {
		const res = classifyResponse(mkResponse(status), Date.now());
		expect(res.kind).toBe("permanent");
	});

	it("treats 307 as retryable", () => {
		const res = classifyResponse(mkResponse(307), Date.now());
		expect(res.kind).toBe("retryable");
	});

	it("treats 429 as retryable and honors Retry-After", () => {
		const res = classifyResponse(
			mkResponse(429, { "retry-after": "2" }),
			Date.now(),
		);
		expect(res.kind).toBe("retryable");
		if (res.kind === "retryable") expect(res.retryAfterMs).toBe(2000);
	});

	it("treats 4xx (non-429) as permanent", () => {
		expect(classifyResponse(mkResponse(400), Date.now()).kind).toBe(
			"permanent",
		);
		expect(classifyResponse(mkResponse(404), Date.now()).kind).toBe(
			"permanent",
		);
	});

	it("treats 5xx as retryable", () => {
		expect(classifyResponse(mkResponse(500), Date.now()).kind).toBe(
			"retryable",
		);
		expect(classifyResponse(mkResponse(503), Date.now()).kind).toBe(
			"retryable",
		);
	});
});

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
				attemptCount: 1,
			});
			expect(event.event).toBe("email.received");
			expect(event.email.headers.message_id).toBe("<unit-test-1@example.com>");
			expect(event.email.smtp.rcpt_to).toEqual(["bob@example.com"]);
			expect(event.email.parsed.attachments_download_url).toBeNull();
			// Inline raw.data for small emails
			expect(event.email.content.raw.included).toBe(true);
			expect(event.email.content.download.url).toContain("/raw/");
			expect(event.email.content.download.url).toContain("token=");
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
		__resetRotationCounterForTests();
	});
	afterEach(async () => {
		await rm(tmp.dir, { recursive: true, force: true });
	});

	it("delivers on first 2xx and logs delivered status", async () => {
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
			fetchImpl: fetchImpl as unknown as typeof fetch,
			sleep: async () => {},
		});
		expect(outcome.status).toBe("delivered");
		expect(outcome.attempts).toBe(1);
		expect(outcome.confirmed).toBe(true);

		const log = await readFile(deliveriesJsonlPath, "utf-8");
		const line = JSON.parse(log.trim());
		expect(line.status).toBe("delivered");
		expect(line.confirmed).toBe(true);
		expect(line.attempts).toBe(1);
	});

	it("retries on 500 and eventually succeeds", async () => {
		let attempts = 0;
		const fetchImpl = vi.fn(async () => {
			attempts += 1;
			if (attempts < 3) return new Response("", { status: 503 });
			return new Response("", { status: 200 });
		});
		const outcome = await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			fetchImpl: fetchImpl as unknown as typeof fetch,
			sleep: async () => {},
		});
		expect(outcome.status).toBe("delivered");
		expect(outcome.attempts).toBe(3);
	});

	it("stops on 400 with permanent failure", async () => {
		const fetchImpl = vi.fn(async () => new Response("", { status: 400 }));
		const outcome = await deliverEvent({
			config: makeConfig({ maxAttempts: 5 }),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			fetchImpl: fetchImpl as unknown as typeof fetch,
			sleep: async () => {},
		});
		expect(outcome.status).toBe("failed");
		expect(outcome.attempts).toBe(1);
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("classifies 308 as redirect-endpoint-moved and stops immediately", async () => {
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
			fetchImpl: fetchImpl as unknown as typeof fetch,
			sleep: async () => {},
		});
		expect(outcome.status).toBe("redirect-endpoint-moved");
		expect(fetchImpl).toHaveBeenCalledTimes(1);
	});

	it("calls fetch with redirect: manual to refuse following", async () => {
		const fetchImpl = vi.fn(async () => new Response("", { status: 200 }));
		await deliverEvent({
			config: makeConfig(),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			fetchImpl: fetchImpl as unknown as typeof fetch,
			sleep: async () => {},
		});
		const [, init] = fetchImpl.mock.calls[0] as unknown as [
			string,
			RequestInit,
		];
		expect(init.redirect).toBe("manual");
	});

	it("regenerates signature timestamp per attempt", async () => {
		const timestamps: string[] = [];
		const fetchImpl = vi.fn(async (_url: string, init: RequestInit) => {
			const headers = init.headers as Record<string, string>;
			const sig = headers["Primitive-Signature"] ?? "";
			const match = sig.match(/t=(\d+)/);
			if (match) timestamps.push(match[1]);
			return new Response("", { status: 500 });
		});
		let fakeNow = 1_700_000_000_000;
		const now = () => {
			fakeNow += 2_000;
			return fakeNow;
		};
		await deliverEvent({
			config: makeConfig({ maxAttempts: 3 }),
			canonicalJsonPath: tmp.canonicalJsonPath,
			emlPath: tmp.emlPath,
			id: tmp.id,
			seq: 1,
			domain: tmp.domain,
			deliveriesJsonlPath,
			fetchImpl: fetchImpl as unknown as typeof fetch,
			now,
			sleep: async () => {},
		});
		expect(new Set(timestamps).size).toBe(timestamps.length);
		expect(timestamps.length).toBeGreaterThanOrEqual(3);
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
			fetchImpl: fetchImpl as unknown as typeof fetch,
			sleep: async () => {},
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
		// Remove the .eml so the pre-flight check fires.
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
			fetchImpl: fetchImpl as unknown as typeof fetch,
			sleep: async () => {},
		});
		expect(outcome.status).toBe("skipped");
		expect(fetchImpl).not.toHaveBeenCalled();
	});
});

describe("delivery-log rotation", () => {
	it("rotates when size exceeds soft cap", async () => {
		const dir = await mkdtemp(join(tmpdir(), "delivery-log-"));
		const path = join(dir, "deliveries.jsonl");
		// Write something slightly larger than the cap
		const big = Buffer.alloc(DELIVERY_LOG_SOFT_CAP_BYTES + 100, "x");
		await writeFile(path, big);
		const rotated = await maybeRotate(path);
		expect(rotated).toBe(true);
		const rotatedStat = await stat(`${path}.1`).catch(() => null);
		expect(rotatedStat).not.toBeNull();
		// Original should be gone (rename, not truncate)
		const origStat = await stat(path).catch(() => null);
		expect(origStat).toBeNull();
		await rm(dir, { recursive: true, force: true });
	});

	it("does not rotate when under the soft cap", async () => {
		const dir = await mkdtemp(join(tmpdir(), "delivery-log-"));
		const path = join(dir, "deliveries.jsonl");
		await writeFile(path, "small\n");
		expect(await maybeRotate(path)).toBe(false);
		await rm(dir, { recursive: true, force: true });
	});
});
