/**
 * Embedded HTTP download server.
 *
 * Serves per-email `.eml` bytes and attachment tarballs to webhook
 * receivers. Authentication is via signed tokens issued by the deliverer
 * and verified with `verifyDownloadToken` from the SDK. Tokens are time-
 * bound (15 min default), constant-time compared, and scoped to a specific
 * email id + audience.
 *
 * Routes:
 *   GET /raw/:id?token=...         → streams <domain>/<id>.eml
 *   GET /attachments/:id?token=... → streams <domain>/<id>.attachments.tar.gz
 *   GET /healthz                   → 200 "ok"
 *   *                              → 404
 *
 * Token validation happens BEFORE any filesystem lookup. Invalid tokens
 * never reveal whether a given id exists.
 */

import { createReadStream } from "node:fs";
import { readdir, stat } from "node:fs/promises";
import {
	type IncomingMessage,
	type Server,
	type ServerResponse,
	createServer,
} from "node:http";
import { join } from "node:path";
import { verifyDownloadToken } from "@primitivedotdev/sdk/webhook";
import { AUDIENCE_ATTACHMENTS, AUDIENCE_RAW } from "./delivery.js";

export interface DownloadServerOptions {
	port: number;
	secret: string;
	mailDir: string;
	/** Optional hostname/IP to bind. Defaults to 0.0.0.0 (all interfaces). */
	host?: string;
}

export interface StartedDownloadServer {
	/** Actual bound port (useful when `port: 0` was passed to let the OS pick). */
	port: number;
	close(): Promise<void>;
}

/**
 * Start the download server. Resolves once the listener is bound.
 */
export function startDownloadServer(
	options: DownloadServerOptions,
): Promise<StartedDownloadServer> {
	const server = createServer((req, res) => {
		handleRequest(req, res, options).catch((err) => {
			console.error("[download] handler threw:", err);
			if (!res.headersSent) {
				res.writeHead(500, { "Content-Type": "text/plain" }).end("error");
			} else {
				res.destroy();
			}
		});
	});

	return new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(options.port, options.host ?? "0.0.0.0", () => {
			const address = server.address();
			const boundPort =
				typeof address === "object" && address ? address.port : options.port;
			server.removeListener("error", reject);
			resolve({
				port: boundPort,
				close: () => closeServer(server),
			});
		});
	});
}

function closeServer(server: Server): Promise<void> {
	return new Promise((resolve, reject) => {
		server.close((err) => (err ? reject(err) : resolve()));
	});
}

/**
 * Handle one incoming HTTP request. Only GET is supported on a small set
 * of routes; everything else is 404 (not 405 — we don't want to advertise
 * the shape).
 */
async function handleRequest(
	req: IncomingMessage,
	res: ServerResponse,
	options: DownloadServerOptions,
): Promise<void> {
	if (req.method !== "GET" || !req.url) {
		res.writeHead(404).end();
		return;
	}

	const url = new URL(req.url, "http://localhost");

	if (url.pathname === "/healthz") {
		res.writeHead(200, { "Content-Type": "text/plain" }).end("ok");
		return;
	}

	const rawMatch = url.pathname.match(/^\/raw\/([^/]+)$/);
	const attMatch = url.pathname.match(/^\/attachments\/([^/]+)$/);

	const match = rawMatch ?? attMatch;
	if (!match) {
		res.writeHead(404).end();
		return;
	}

	const emailId = decodeURIComponent(match[1]);
	// Defense-in-depth: reject any decoded id that could escape the mail
	// directory. The pathname regex blocks literal `/`, but `decodeURIComponent`
	// turns `%2F` into `/`, so a caller with a valid token could otherwise
	// traverse upward. Token verification gates this, but we refuse suspicious
	// ids before any filesystem work.
	if (!isSafeEmailId(emailId)) {
		res.writeHead(400, { "Content-Type": "text/plain" }).end("bad request");
		logAccess({
			route: rawMatch ? "raw" : "attachments",
			emailId: "<unsafe>",
			status: 400,
		});
		return;
	}
	const audience = rawMatch ? AUDIENCE_RAW : AUDIENCE_ATTACHMENTS;
	const token = url.searchParams.get("token") ?? "";

	const verification = verifyDownloadToken({
		token,
		emailId,
		audience,
		secret: options.secret,
	});
	if (!verification.valid) {
		const code = verification.error.toLowerCase().includes("expired")
			? 410
			: 401;
		res
			.writeHead(code, { "Content-Type": "text/plain" })
			.end(code === 410 ? "gone" : "unauthorized");
		logAccess({
			route: rawMatch ? "raw" : "attachments",
			emailId,
			status: code,
		});
		return;
	}

	const filename = rawMatch
		? `${emailId}.eml`
		: `${emailId}.attachments.tar.gz`;
	const located = await locateFile(options.mailDir, filename);

	if (located.kind === "not_found") {
		res.writeHead(404, { "Content-Type": "text/plain" }).end("not found");
		logAccess({
			route: rawMatch ? "raw" : "attachments",
			emailId,
			status: 404,
		});
		return;
	}
	if (located.kind === "conflict") {
		res
			.writeHead(409, { "Content-Type": "text/plain" })
			.end("id collision across domains");
		logAccess({
			route: rawMatch ? "raw" : "attachments",
			emailId,
			status: 409,
		});
		return;
	}

	const st = await stat(located.path).catch(() => null);
	if (!st) {
		res.writeHead(404, { "Content-Type": "text/plain" }).end("not found");
		logAccess({
			route: rawMatch ? "raw" : "attachments",
			emailId,
			status: 404,
		});
		return;
	}

	res.writeHead(200, {
		"Content-Type": rawMatch ? "message/rfc822" : "application/gzip",
		"Content-Length": String(st.size),
	});
	const stream = createReadStream(located.path);
	stream.on("error", () => {
		res.destroy();
	});
	stream.pipe(res);
	logAccess({ route: rawMatch ? "raw" : "attachments", emailId, status: 200 });
}

/**
 * Email ids are generated by the milter as `YYYYMMDDTHHMMSSZ-<nonce>`,
 * constrained to a small alphabet. We accept that shape and nothing else.
 * Explicitly refuse any path separators, `..`, null bytes, or control
 * characters even after `decodeURIComponent`.
 */
function isSafeEmailId(id: string): boolean {
	if (id.length === 0 || id.length > 128) return false;
	if (id.includes("/") || id.includes("\\")) return false;
	if (id.includes("..")) return false;
	// biome-ignore lint/suspicious/noControlCharactersInRegex: intentional — reject ids with control bytes
	if (/[\x00-\x1f\x7f]/.test(id)) return false;
	return /^[A-Za-z0-9._-]+$/.test(id);
}

type LocateResult =
	| { kind: "found"; path: string }
	| { kind: "not_found" }
	| { kind: "conflict" };

/**
 * Find <mailDir>/<domain>/<filename>, searching all domain subdirectories.
 * Returns conflict if the same filename appears under two domains — realistically
 * this should never happen because ids include a timestamp plus a nonce.
 */
async function locateFile(
	mailDir: string,
	filename: string,
): Promise<LocateResult> {
	let entries: string[];
	try {
		entries = await readdir(mailDir);
	} catch {
		return { kind: "not_found" };
	}

	const matches: string[] = [];
	for (const entry of entries) {
		if (entry.startsWith(".")) continue;
		const candidate = join(mailDir, entry, filename);
		const st = await stat(candidate).catch(() => null);
		if (st?.isFile()) matches.push(candidate);
	}

	if (matches.length === 0) return { kind: "not_found" };
	if (matches.length > 1) return { kind: "conflict" };
	return { kind: "found", path: matches[0] };
}

function logAccess(info: {
	route: string;
	emailId: string;
	status: number;
}): void {
	// Never log tokens or full URLs — just the triple the operator cares about.
	console.log(
		`[download] route=${info.route} id=${info.emailId} status=${info.status}`,
	);
}
