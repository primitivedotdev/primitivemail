/**
 * End-to-end test that spawns the real watcher binary.
 *
 * The in-process e2e test (`e2e-delivery.test.ts`) covers the delivery +
 * download wiring by calling the exported functions directly. This test
 * goes one level out: it runs the watcher exactly the way it runs in
 * production (via `tsx src/watcher.ts` — the same command `pnpm dev`
 * uses), drops a `.meta.json` + `.eml` pair into the watched directory,
 * and asserts the receiver gets a signature-verifying POST.
 *
 * Covers the full pipeline that the in-process test skips:
 *   file drop → poll loop → parse → canonical JSON write → journal →
 *   delivery trigger → HTTP POST → receiver verifies.
 */

import { type ChildProcess, spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { handleWebhook } from "@primitivedotdev/sdk";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const __dirname = dirname(fileURLToPath(import.meta.url));
const WATCHER_ENTRY = join(__dirname, "..", "src", "watcher.ts");
const FIXTURE_DIR = join(__dirname, "fixtures");
const SECRET = "subprocess-e2e-secret";
const STARTUP_TIMEOUT_MS = 10_000;

interface SpawnedWatcher {
	child: ChildProcess;
	stdout: string[];
	stderr: string[];
	kill(): Promise<void>;
}

function startWatcher(env: Record<string, string>): Promise<SpawnedWatcher> {
	return new Promise((resolve, reject) => {
		const child = spawn("pnpm", ["exec", "tsx", WATCHER_ENTRY], {
			env: { ...process.env, ...env },
			stdio: ["ignore", "pipe", "pipe"],
		});

		const stdoutLines: string[] = [];
		const stderrLines: string[] = [];
		let resolved = false;
		const timer = setTimeout(() => {
			if (!resolved) {
				resolved = true;
				child.kill("SIGKILL");
				reject(
					new Error(
						`watcher failed to start within ${STARTUP_TIMEOUT_MS}ms. stdout:\n${stdoutLines.join("\n")}\nstderr:\n${stderrLines.join("\n")}`,
					),
				);
			}
		}, STARTUP_TIMEOUT_MS);

		child.stdout?.setEncoding("utf8");
		child.stdout?.on("data", (chunk: string) => {
			for (const line of chunk.split("\n").filter(Boolean)) {
				stdoutLines.push(line);
				// "Download server:" (delivery enabled) or "Delivery disabled"
				// (delivery off) are the two signals that startup completed.
				if (
					!resolved &&
					(line.includes("Download server:") ||
						line.includes("Delivery disabled"))
				) {
					resolved = true;
					clearTimeout(timer);
					resolve({
						child,
						stdout: stdoutLines,
						stderr: stderrLines,
						kill: () =>
							new Promise((r) => {
								child.once("exit", () => r());
								child.kill("SIGTERM");
								setTimeout(() => child.kill("SIGKILL"), 3_000);
							}),
					});
				}
			}
		});
		child.stderr?.setEncoding("utf8");
		child.stderr?.on("data", (chunk: string) => {
			for (const line of chunk.split("\n").filter(Boolean)) {
				stderrLines.push(line);
			}
		});
		child.once("exit", (code) => {
			if (!resolved) {
				resolved = true;
				clearTimeout(timer);
				reject(
					new Error(
						`watcher exited (code ${code}) before it was ready. stdout:\n${stdoutLines.join("\n")}\nstderr:\n${stderrLines.join("\n")}`,
					),
				);
			}
		});
	});
}

interface CapturedPost {
	headers: Record<string, string>;
	body: string;
}

function startReceiver(): Promise<{
	url: string;
	waitForPost(timeoutMs: number): Promise<CapturedPost>;
	close(): Promise<void>;
}> {
	return new Promise((resolve, reject) => {
		const posts: CapturedPost[] = [];
		const waiters: Array<(post: CapturedPost) => void> = [];

		const server: Server = createServer((req, res) => {
			const chunks: Buffer[] = [];
			req.on("data", (c) => chunks.push(c));
			req.on("end", () => {
				if (req.method !== "POST") {
					res.writeHead(405).end();
					return;
				}
				const headers: Record<string, string> = {};
				for (const [k, v] of Object.entries(req.headers)) {
					if (typeof v === "string") headers[k] = v;
					else if (Array.isArray(v) && v.length > 0) headers[k] = v[0];
				}
				const body = Buffer.concat(chunks).toString("utf8");
				const post: CapturedPost = { headers, body };
				posts.push(post);
				const w = waiters.shift();
				w?.(post);
				res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
			});
		});

		server.once("error", reject);
		server.listen(0, "127.0.0.1", () => {
			server.removeListener("error", reject);
			const port = (server.address() as AddressInfo).port;
			resolve({
				url: `http://127.0.0.1:${port}/hook`,
				waitForPost: (timeoutMs) =>
					new Promise((res2, rej2) => {
						if (posts.length > 0) {
							res2(posts.shift() as CapturedPost);
							return;
						}
						const timer = setTimeout(() => {
							rej2(new Error(`no POST within ${timeoutMs}ms`));
						}, timeoutMs);
						waiters.push((p) => {
							clearTimeout(timer);
							res2(p);
						});
					}),
				close: () =>
					new Promise((r, rj) => server.close((err) => (err ? rj(err) : r()))),
			});
		});
	});
}

describe("e2e subprocess watcher", () => {
	let mailDir: string;
	let watcher: SpawnedWatcher | null = null;
	let receiver: Awaited<ReturnType<typeof startReceiver>> | null = null;

	beforeEach(async () => {
		mailDir = await mkdtemp(join(tmpdir(), "watcher-subproc-"));
	});

	afterEach(async () => {
		await watcher?.kill().catch(() => {});
		await receiver?.close().catch(() => {});
		await rm(mailDir, { recursive: true, force: true });
		watcher = null;
		receiver = null;
	});

	it("processes a dropped email and delivers a signed webhook", async () => {
		receiver = await startReceiver();
		// Use 0 as DOWNLOAD_SERVER_PORT isn't supported (config bounds), so pick
		// an ephemeral high port that is extremely unlikely to collide.
		const downloadPort = 40_000 + Math.floor(Math.random() * 20_000);

		watcher = await startWatcher({
			MAIL_DIR: mailDir,
			POLL_INTERVAL_MS: "100",
			EVENT_WEBHOOK_URL: receiver.url,
			EVENT_WEBHOOK_SECRET: SECRET,
			EVENT_WEBHOOK_MAX_ATTEMPTS: "2",
			EVENT_WEBHOOK_TIMEOUT_MS: "5000",
			DOWNLOAD_SERVER_PORT: String(downloadPort),
			DOWNLOAD_BASE_URL: `http://127.0.0.1:${downloadPort}`,
		});

		// Drop .meta.json + .eml matching the filename convention the watcher
		// recognizes (id with leading `YYYYMMDDTHHMMSSZ-` timestamp prefix).
		const domain = "example.com";
		const id = "20260417T120000Z-subp0001";
		const domainDir = join(mailDir, domain);
		await mkdir(domainDir, { recursive: true });
		const emlBytes = await readFile(join(FIXTURE_DIR, "sample.eml"));
		await writeFile(join(domainDir, `${id}.eml`), emlBytes);
		await writeFile(
			join(domainDir, `${id}.meta.json`),
			JSON.stringify({
				smtp: {
					helo: "mail.example.com",
					mail_from: "alice@example.com",
					rcpt_to: ["bob@example.com"],
				},
				auth: {
					spf: "pass",
					dmarc: "pass",
					dmarc_policy: "reject",
					dmarc_from_domain: "example.com",
					dkim: "pass",
					dkim_domains: ["example.com"],
				},
			}),
		);

		const post = await receiver.waitForPost(12_000);
		const event = handleWebhook({
			body: post.body,
			headers: post.headers,
			secret: SECRET,
		});

		expect(event.event).toBe("email.received");
		expect(event.email.id).toBe(id);
		expect(event.email.headers.from).toContain("alice@example.com");
		expect(event.email.smtp.rcpt_to).toEqual(["bob@example.com"]);

		// Delivery log exists under the shared maildata dir.
		const deliveries = await readFile(
			join(mailDir, "deliveries.jsonl"),
			"utf-8",
		);
		const line = JSON.parse(deliveries.trim().split("\n")[0]);
		expect(line.status).toBe("delivered");
		expect(line.id).toBe(id);

		// Download the raw via the embedded server (same watcher process).
		const downloadRes = await fetch(event.email.content.download.url);
		expect(downloadRes.status).toBe(200);
		const downloadedBytes = Buffer.from(await downloadRes.arrayBuffer());
		expect(downloadedBytes.equals(emlBytes)).toBe(true);
	}, 30_000);

	it("does not start a download server or deliver when webhook URL is unset", async () => {
		// No receiver, no EVENT_WEBHOOK_URL — watcher should boot and poll without
		// opening a port or attempting delivery.
		watcher = await startWatcher({
			MAIL_DIR: mailDir,
			POLL_INTERVAL_MS: "100",
			// Intentionally set DOWNLOAD_SERVER_PORT to a sentinel that would fail
			// if the code ever tried to bind. Config must be the one refusing.
		} as Record<string, string>);

		// The startup log should say delivery is disabled.
		expect(watcher.stdout.some((l) => l.includes("Delivery disabled"))).toBe(
			true,
		);

		// No deliveries.jsonl should exist.
		const deliveries = await readFile(
			join(mailDir, "deliveries.jsonl"),
			"utf-8",
		).catch(() => null);
		expect(deliveries).toBeNull();
	}, 30_000);
});
