/**
 * End-to-end integration test for the delivery + download round-trip.
 *
 * Wires up the three real components in-process:
 *
 *   canonical JSON + .eml on disk
 *           │
 *           ▼
 *   deliverEvent (signs + POSTs)
 *           │
 *           ▼
 *   local HTTP receiver (verifies signature with SDK's handleWebhook)
 *           │
 *           ▼
 *   follows event.email.content.download.url
 *           │
 *           ▼
 *   watcher's download server (verifies token + streams .eml)
 *
 * The test asserts the webhook POST verifies with handleWebhook, the
 * event round-trips back through the download URL, and the downloaded
 * bytes match what was originally written.
 */

import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import {
	type IncomingMessage,
	type Server,
	type ServerResponse,
	createServer,
} from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { handleWebhook } from "@primitivedotdev/sdk";
import { afterEach, describe, expect, it } from "vitest";
import type { DeliveryConfig } from "../src/config.js";
import { computeEndpointId } from "../src/config.js";
import { deliverEvent } from "../src/delivery.js";
import {
	type StartedDownloadServer,
	startDownloadServer,
} from "../src/download-server.js";

const SECRET = "e2e-test-secret-value";
const FIXTURE_DIR = join(__dirname, "fixtures");

interface CapturedPost {
	headers: Record<string, string>;
	body: string;
}

interface Receiver {
	url: string;
	lastPost(): CapturedPost | null;
	close(): Promise<void>;
}

/**
 * Minimal HTTP receiver that accepts POSTs and returns 200.
 * Captures the last request so tests can assert on headers/body.
 */
async function startReceiver(
	options: {
		onPost?: (
			req: CapturedPost,
		) => { status?: number; headers?: Record<string, string> } | undefined;
	} = {},
): Promise<Receiver> {
	let lastPost: CapturedPost | null = null;

	const server: Server = createServer(
		(req: IncomingMessage, res: ServerResponse) => {
			if (req.method !== "POST") {
				res.writeHead(405).end();
				return;
			}
			const chunks: Buffer[] = [];
			req.on("data", (chunk) => chunks.push(chunk));
			req.on("end", () => {
				const body = Buffer.concat(chunks).toString("utf8");
				const headers: Record<string, string> = {};
				for (const [k, v] of Object.entries(req.headers)) {
					if (typeof v === "string") headers[k] = v;
					else if (Array.isArray(v) && v.length > 0) headers[k] = v[0];
				}
				lastPost = { headers, body };
				const override = options.onPost?.({ headers, body }) ?? {};
				res.writeHead(override.status ?? 200, {
					"Content-Type": "application/json",
					...override.headers,
				});
				res.end("{}");
			});
		},
	);

	await new Promise<void>((resolve, reject) => {
		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			server.removeListener("error", reject);
			resolve();
		});
	});
	const port = (server.address() as AddressInfo).port;

	return {
		url: `http://127.0.0.1:${port}/hook`,
		lastPost: () => lastPost,
		close: () =>
			new Promise((resolve, reject) =>
				server.close((err) => (err ? reject(err) : resolve())),
			),
	};
}

interface E2ESetup {
	mailDir: string;
	canonicalJsonPath: string;
	emlPath: string;
	id: string;
	domain: string;
	emlBytes: Buffer;
	receiver: Receiver;
	downloadServer: StartedDownloadServer;
	config: DeliveryConfig;
	deliveriesJsonlPath: string;
	cleanup: () => Promise<void>;
}

async function setupE2E(
	receiverOptions: Parameters<typeof startReceiver>[0] = {},
): Promise<E2ESetup> {
	const mailDir = await mkdtemp(join(tmpdir(), "watcher-e2e-"));
	const domain = "example.com";
	const id = "20260417T120000Z-e2e00001";
	const domainDir = join(mailDir, domain);
	await mkdir(domainDir, { recursive: true });

	const canonicalJsonPath = join(domainDir, `${id}.json`);
	const emlPath = join(domainDir, `${id}.eml`);
	const deliveriesJsonlPath = join(mailDir, "deliveries.jsonl");

	// Seed the email files — in the real watcher the processEmail() fn writes
	// these. We reuse the unit-test fixture with a rewritten id.
	const fixtureJson = JSON.parse(
		await readFile(join(FIXTURE_DIR, "sample.json"), "utf-8"),
	);
	fixtureJson.id = id;
	fixtureJson.content.raw_path = `${domain}/${id}.eml`;
	await writeFile(canonicalJsonPath, JSON.stringify(fixtureJson));
	const emlBytes = await readFile(join(FIXTURE_DIR, "sample.eml"));
	await writeFile(emlPath, emlBytes);

	const receiver = await startReceiver(receiverOptions);

	const downloadServer = await startDownloadServer({
		port: 0,
		secret: SECRET,
		mailDir,
		host: "127.0.0.1",
	});

	const config: DeliveryConfig = {
		enabled: true,
		webhookUrl: receiver.url,
		webhookSecret: SECRET,
		maxAttempts: 3,
		timeoutMs: 5_000,
		downloadServerPort: downloadServer.port,
		downloadBaseUrl: `http://127.0.0.1:${downloadServer.port}`,
		endpointId: computeEndpointId(receiver.url, SECRET),
	};

	return {
		mailDir,
		canonicalJsonPath,
		emlPath,
		id,
		domain,
		emlBytes,
		receiver,
		downloadServer,
		config,
		deliveriesJsonlPath,
		cleanup: async () => {
			await downloadServer.close().catch(() => {});
			await receiver.close().catch(() => {});
			await rm(mailDir, { recursive: true, force: true });
		},
	};
}

describe("e2e delivery + download round-trip", () => {
	let fx: E2ESetup;

	afterEach(async () => {
		await fx?.cleanup();
	});

	it("signs, delivers, and the receiver can verify + fetch raw bytes", async () => {
		fx = await setupE2E();

		const outcome = await deliverEvent({
			config: fx.config,
			canonicalJsonPath: fx.canonicalJsonPath,
			emlPath: fx.emlPath,
			id: fx.id,
			seq: 1,
			domain: fx.domain,
			deliveriesJsonlPath: fx.deliveriesJsonlPath,
			sleep: async () => {},
		});

		expect(outcome.status).toBe("delivered");
		expect(outcome.attempts).toBe(1);

		// Receiver got the POST and handleWebhook verifies the signature end-to-end.
		const captured = fx.receiver.lastPost();
		expect(captured).not.toBeNull();
		if (!captured) throw new Error("no POST captured");

		const event = handleWebhook({
			body: captured.body,
			headers: captured.headers,
			secret: SECRET,
		});
		expect(event.event).toBe("email.received");
		expect(event.email.id).toBe(fx.id);
		expect(event.delivery.endpoint_id).toBe(fx.config.endpointId);

		// Event carries an inline raw.data for the small sample email, but also a
		// download URL pointing at the watcher's download server. Follow it and
		// assert the bytes match what the watcher wrote.
		const downloadUrl = event.email.content.download.url;
		expect(downloadUrl.startsWith(fx.config.downloadBaseUrl)).toBe(true);
		const downloadRes = await fetch(downloadUrl);
		expect(downloadRes.status).toBe(200);
		const downloadedBytes = Buffer.from(await downloadRes.arrayBuffer());
		expect(downloadedBytes.equals(fx.emlBytes)).toBe(true);

		// Delivery log records success.
		const log = await readFile(fx.deliveriesJsonlPath, "utf-8");
		const line = JSON.parse(log.trim());
		expect(line.status).toBe("delivered");
		expect(line.seq).toBe(1);
	});

	it("carries confirmed=true when receiver returns Primitive-Confirmed: true", async () => {
		fx = await setupE2E({
			onPost: () => ({
				status: 200,
				headers: { "Primitive-Confirmed": "true" },
			}),
		});
		const outcome = await deliverEvent({
			config: fx.config,
			canonicalJsonPath: fx.canonicalJsonPath,
			emlPath: fx.emlPath,
			id: fx.id,
			seq: 1,
			domain: fx.domain,
			deliveriesJsonlPath: fx.deliveriesJsonlPath,
			sleep: async () => {},
		});
		expect(outcome.status).toBe("delivered");
		expect(outcome.confirmed).toBe(true);
	});

	it("retries when the receiver returns 500 then succeeds", async () => {
		let attempt = 0;
		fx = await setupE2E({
			onPost: () => {
				attempt += 1;
				return attempt < 3 ? { status: 500 } : { status: 200 };
			},
		});

		const outcome = await deliverEvent({
			config: fx.config,
			canonicalJsonPath: fx.canonicalJsonPath,
			emlPath: fx.emlPath,
			id: fx.id,
			seq: 1,
			domain: fx.domain,
			deliveriesJsonlPath: fx.deliveriesJsonlPath,
			sleep: async () => {},
		});

		expect(outcome.status).toBe("delivered");
		expect(outcome.attempts).toBe(3);
	});

	it("stops and logs failed status when receiver returns 400", async () => {
		fx = await setupE2E({
			onPost: () => ({ status: 400 }),
		});

		const outcome = await deliverEvent({
			config: fx.config,
			canonicalJsonPath: fx.canonicalJsonPath,
			emlPath: fx.emlPath,
			id: fx.id,
			seq: 1,
			domain: fx.domain,
			deliveriesJsonlPath: fx.deliveriesJsonlPath,
			sleep: async () => {},
		});

		expect(outcome.status).toBe("failed");
		expect(outcome.attempts).toBe(1);

		const log = await readFile(fx.deliveriesJsonlPath, "utf-8");
		const line = JSON.parse(log.trim());
		expect(line.status).toBe("failed");
		expect(line.status_code).toBe(400);
	});

	it("the download URL in the payload fails with 401 if secret is rotated", async () => {
		fx = await setupE2E();
		const outcome = await deliverEvent({
			config: fx.config,
			canonicalJsonPath: fx.canonicalJsonPath,
			emlPath: fx.emlPath,
			id: fx.id,
			seq: 1,
			domain: fx.domain,
			deliveriesJsonlPath: fx.deliveriesJsonlPath,
			sleep: async () => {},
		});
		expect(outcome.status).toBe("delivered");

		const captured = fx.receiver.lastPost();
		if (!captured) throw new Error("no POST captured");
		const event = handleWebhook({
			body: captured.body,
			headers: captured.headers,
			secret: SECRET,
		});

		// Simulate a new watcher process with a different secret: stop the old
		// server, start a new one pointing at the same mailDir with a different
		// secret. Old tokens must no longer verify.
		await fx.downloadServer.close();
		const rotated = await startDownloadServer({
			port: fx.downloadServer.port,
			secret: "new-rotated-secret",
			mailDir: fx.mailDir,
			host: "127.0.0.1",
		});
		try {
			const res = await fetch(event.email.content.download.url);
			expect(res.status).toBe(401);
		} finally {
			await rotated.close();
		}
	});
});
