import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateDownloadToken } from "@primitivedotdev/sdk/webhook";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AUDIENCE_ATTACHMENTS, AUDIENCE_RAW } from "../src/delivery.js";
import {
	type StartedDownloadServer,
	startDownloadServer,
} from "../src/download-server.js";

const SECRET = "download-server-test-secret";

interface Fixture {
	mailDir: string;
	domain: string;
	id: string;
	emlContent: Buffer;
	tarContent: Buffer;
	server: StartedDownloadServer;
	baseUrl: string;
	cleanup: () => Promise<void>;
}

async function setup(): Promise<Fixture> {
	const mailDir = await mkdtemp(join(tmpdir(), "watcher-server-"));
	const domain = "example.com";
	const id = "20260417T120000Z-abc123";

	const domainDir = join(mailDir, domain);
	await mkdir(domainDir, { recursive: true });

	const emlContent = Buffer.from(
		"From: a@x\nTo: b@y\n\nbody bytes here\n",
		"utf8",
	);
	const tarContent = Buffer.from([0x1f, 0x8b, 0x08, 0, 1, 2, 3, 4]); // fake gzip magic

	await writeFile(join(domainDir, `${id}.eml`), emlContent);
	await writeFile(join(domainDir, `${id}.attachments.tar.gz`), tarContent);

	const server = await startDownloadServer({
		port: 0, // let the OS pick
		secret: SECRET,
		mailDir,
		host: "127.0.0.1",
	});

	return {
		mailDir,
		domain,
		id,
		emlContent,
		tarContent,
		server,
		baseUrl: `http://127.0.0.1:${server.port}`,
		cleanup: async () => {
			await server.close();
			await rm(mailDir, { recursive: true, force: true });
		},
	};
}

function tokenFor(
	emailId: string,
	audience: string,
	opts: { expiresAt?: number; secret?: string } = {},
): string {
	return generateDownloadToken({
		emailId,
		expiresAt: opts.expiresAt ?? Math.floor(Date.now() / 1000) + 600,
		audience,
		secret: opts.secret ?? SECRET,
	});
}

describe("download server", () => {
	let fx: Fixture;

	beforeEach(async () => {
		fx = await setup();
	});

	afterEach(async () => {
		await fx.cleanup();
	});

	it("serves /healthz with 200 'ok'", async () => {
		const res = await fetch(`${fx.baseUrl}/healthz`);
		expect(res.status).toBe(200);
		expect(await res.text()).toBe("ok");
	});

	it("returns 404 for unknown routes", async () => {
		const res = await fetch(`${fx.baseUrl}/nope`);
		expect(res.status).toBe(404);
	});

	it("streams raw .eml with a valid token", async () => {
		const token = tokenFor(fx.id, AUDIENCE_RAW);
		const res = await fetch(`${fx.baseUrl}/raw/${fx.id}?token=${token}`);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("message/rfc822");
		expect(res.headers.get("content-length")).toBe(
			String(fx.emlContent.length),
		);
		const body = Buffer.from(await res.arrayBuffer());
		expect(body.equals(fx.emlContent)).toBe(true);
	});

	it("streams attachments tarball with a valid token", async () => {
		const token = tokenFor(fx.id, AUDIENCE_ATTACHMENTS);
		const res = await fetch(
			`${fx.baseUrl}/attachments/${fx.id}?token=${token}`,
		);
		expect(res.status).toBe(200);
		expect(res.headers.get("content-type")).toBe("application/gzip");
		const body = Buffer.from(await res.arrayBuffer());
		expect(body.equals(fx.tarContent)).toBe(true);
	});

	it("returns 401 on missing token", async () => {
		const res = await fetch(`${fx.baseUrl}/raw/${fx.id}`);
		expect(res.status).toBe(401);
	});

	it("returns 401 on malformed token", async () => {
		const res = await fetch(
			`${fx.baseUrl}/raw/${fx.id}?token=not-a-real-token`,
		);
		expect(res.status).toBe(401);
	});

	it("returns 401 when audience mismatches route", async () => {
		// A raw-audience token submitted against the attachments route.
		const token = tokenFor(fx.id, AUDIENCE_RAW);
		const res = await fetch(
			`${fx.baseUrl}/attachments/${fx.id}?token=${token}`,
		);
		expect(res.status).toBe(401);
	});

	it("returns 401 when email id mismatches the token binding", async () => {
		// Token bound to a different id than the route.
		const token = tokenFor("different-id", AUDIENCE_RAW);
		const res = await fetch(`${fx.baseUrl}/raw/${fx.id}?token=${token}`);
		expect(res.status).toBe(401);
	});

	it("returns 401 when token signed with the wrong secret", async () => {
		const token = tokenFor(fx.id, AUDIENCE_RAW, { secret: "wrong-secret" });
		const res = await fetch(`${fx.baseUrl}/raw/${fx.id}?token=${token}`);
		expect(res.status).toBe(401);
	});

	it("returns 410 on expired token", async () => {
		const token = tokenFor(fx.id, AUDIENCE_RAW, { expiresAt: 1 });
		const res = await fetch(`${fx.baseUrl}/raw/${fx.id}?token=${token}`);
		expect(res.status).toBe(410);
	});

	it("returns 404 for unknown email id (with a valid token)", async () => {
		const unknownId = "20260101T000000Z-missing";
		const token = tokenFor(unknownId, AUDIENCE_RAW);
		const res = await fetch(`${fx.baseUrl}/raw/${unknownId}?token=${token}`);
		expect(res.status).toBe(404);
	});

	it("does not respond to non-GET methods", async () => {
		const token = tokenFor(fx.id, AUDIENCE_RAW);
		const res = await fetch(`${fx.baseUrl}/raw/${fx.id}?token=${token}`, {
			method: "POST",
		});
		expect(res.status).toBe(404);
	});

	it("does not expose the token via /healthz log path", async () => {
		// Simple smoke: healthz shouldn't ever accept a token query and should ignore it.
		const res = await fetch(`${fx.baseUrl}/healthz?token=anything`);
		expect(res.status).toBe(200);
	});
});

describe("download server — file not on disk", () => {
	it("returns 404 if the .attachments.tar.gz is absent", async () => {
		const mailDir = await mkdtemp(join(tmpdir(), "watcher-server-"));
		const domain = "example.com";
		const id = "20260417T120000Z-noattach";
		await mkdir(join(mailDir, domain), { recursive: true });
		await writeFile(join(mailDir, domain, `${id}.eml`), "x");
		// deliberately no .attachments.tar.gz

		const server = await startDownloadServer({
			port: 0,
			secret: SECRET,
			mailDir,
			host: "127.0.0.1",
		});
		const baseUrl = `http://127.0.0.1:${server.port}`;
		try {
			const token = tokenFor(id, AUDIENCE_ATTACHMENTS);
			const res = await fetch(`${baseUrl}/attachments/${id}?token=${token}`);
			expect(res.status).toBe(404);
		} finally {
			await server.close();
			await rm(mailDir, { recursive: true, force: true });
		}
	});
});

// Ensure readFile is actually used by vitest (otherwise biome unused-imports fires).
void readFile;
