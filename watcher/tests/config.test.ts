import { describe, expect, it } from "vitest";
import { computeEndpointId, loadDeliveryConfig } from "../src/config.js";

describe("loadDeliveryConfig", () => {
	it("returns disabled when no env vars set", () => {
		const cfg = loadDeliveryConfig({});
		expect(cfg.enabled).toBe(false);
	});

	it("returns enabled config with all defaults when URL+SECRET set", () => {
		const cfg = loadDeliveryConfig({
			EVENT_WEBHOOK_URL: "https://example.com/hook",
			EVENT_WEBHOOK_SECRET: "s3cret",
		});
		expect(cfg.enabled).toBe(true);
		if (cfg.enabled) {
			expect(cfg.webhookUrl).toBe("https://example.com/hook");
			expect(cfg.webhookSecret).toBe("s3cret");
			expect(cfg.timeoutMs).toBe(10_000);
			expect(cfg.downloadServerPort).toBe(4001);
			expect(cfg.downloadBaseUrl).toBe("http://localhost:4001");
			expect(cfg.endpointId).toMatch(/^[0-9a-f]{16}$/);
		}
	});

	it("derives downloadBaseUrl from DOWNLOAD_SERVER_PORT when base URL is unset", () => {
		const cfg = loadDeliveryConfig({
			EVENT_WEBHOOK_URL: "https://example.com/hook",
			EVENT_WEBHOOK_SECRET: "s3cret",
			DOWNLOAD_SERVER_PORT: "9876",
		});
		expect(cfg.enabled && cfg.downloadBaseUrl).toBe("http://localhost:9876");
	});

	it("strips trailing slash from DOWNLOAD_BASE_URL", () => {
		const cfg = loadDeliveryConfig({
			EVENT_WEBHOOK_URL: "https://example.com/hook",
			EVENT_WEBHOOK_SECRET: "s3cret",
			DOWNLOAD_BASE_URL: "http://host.docker.internal:9000/",
		});
		expect(cfg.enabled && cfg.downloadBaseUrl).toBe(
			"http://host.docker.internal:9000",
		);
	});

	it("throws when URL set but SECRET missing", () => {
		expect(() =>
			loadDeliveryConfig({ EVENT_WEBHOOK_URL: "https://example.com/hook" }),
		).toThrow(/EVENT_WEBHOOK_SECRET/);
	});

	it("throws when SECRET set but URL missing", () => {
		expect(() =>
			loadDeliveryConfig({ EVENT_WEBHOOK_SECRET: "s3cret" }),
		).toThrow(/EVENT_WEBHOOK_URL is not/);
	});

	it("throws when URL is not http(s)", () => {
		expect(() =>
			loadDeliveryConfig({
				EVENT_WEBHOOK_URL: "ftp://example.com/hook",
				EVENT_WEBHOOK_SECRET: "s3cret",
			}),
		).toThrow(/http:\/\/ or https:\/\//);
	});

	it("throws when URL is malformed", () => {
		expect(() =>
			loadDeliveryConfig({
				EVENT_WEBHOOK_URL: "not a url",
				EVENT_WEBHOOK_SECRET: "s3cret",
			}),
		).toThrow(/not a valid URL/);
	});

	it("throws on non-integer TIMEOUT_MS", () => {
		expect(() =>
			loadDeliveryConfig({
				EVENT_WEBHOOK_URL: "https://example.com/hook",
				EVENT_WEBHOOK_SECRET: "s3cret",
				EVENT_WEBHOOK_TIMEOUT_MS: "abc",
			}),
		).toThrow(/EVENT_WEBHOOK_TIMEOUT_MS/);
	});

	it("throws when TIMEOUT_MS is out of range", () => {
		expect(() =>
			loadDeliveryConfig({
				EVENT_WEBHOOK_URL: "https://example.com/hook",
				EVENT_WEBHOOK_SECRET: "s3cret",
				EVENT_WEBHOOK_TIMEOUT_MS: "100",
			}),
		).toThrow(/between/);
	});

	it("accepts custom TIMEOUT_MS and PORT within bounds", () => {
		const cfg = loadDeliveryConfig({
			EVENT_WEBHOOK_URL: "https://example.com/hook",
			EVENT_WEBHOOK_SECRET: "s3cret",
			EVENT_WEBHOOK_TIMEOUT_MS: "5000",
			DOWNLOAD_SERVER_PORT: "9876",
		});
		expect(cfg.enabled && cfg.timeoutMs).toBe(5000);
		expect(cfg.enabled && cfg.downloadServerPort).toBe(9876);
	});
});

describe("computeEndpointId", () => {
	it("is stable for the same inputs", () => {
		const a = computeEndpointId("https://example.com/hook", "s3cret");
		const b = computeEndpointId("https://example.com/hook", "s3cret");
		expect(a).toBe(b);
	});

	it("is 16 hex chars", () => {
		const id = computeEndpointId("https://example.com/hook", "s3cret");
		expect(id).toMatch(/^[0-9a-f]{16}$/);
	});

	it("differs when URL changes", () => {
		const a = computeEndpointId("https://example.com/hook", "s3cret");
		const b = computeEndpointId("https://other.example.com/hook", "s3cret");
		expect(a).not.toBe(b);
	});

	it("differs when secret changes", () => {
		const a = computeEndpointId("https://example.com/hook", "s3cret");
		const b = computeEndpointId("https://example.com/hook", "different");
		expect(a).not.toBe(b);
	});
});
