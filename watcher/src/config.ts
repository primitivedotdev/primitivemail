/**
 * Environment-variable surface for the watcher's self-host webhook delivery.
 *
 * When EVENT_WEBHOOK_URL is set, the deliverer and the embedded download
 * server are activated. When unset, the watcher behaves exactly as before:
 * no deliveries, no port binding, no deliveries.jsonl.
 *
 * Call `loadDeliveryConfig()` once at startup. It validates the full env
 * surface atomically so the watcher fails fast on misconfiguration.
 */

import { createHash } from "node:crypto";

export interface DeliveryConfig {
	enabled: true;
	webhookUrl: string;
	webhookSecret: string;
	timeoutMs: number;
	downloadServerPort: number;
	downloadBaseUrl: string;
	/** Stable id derived from URL + secret; written into event.delivery.endpoint_id. */
	endpointId: string;
}

export type LoadedDeliveryConfig = DeliveryConfig | { enabled: false };

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_PORT = 4001;

export interface EnvLike {
	EVENT_WEBHOOK_URL?: string;
	EVENT_WEBHOOK_SECRET?: string;
	EVENT_WEBHOOK_TIMEOUT_MS?: string;
	DOWNLOAD_SERVER_PORT?: string;
	DOWNLOAD_BASE_URL?: string;
}

function parseIntWithBounds(
	raw: string | undefined,
	name: string,
	defaultValue: number,
	min: number,
	max: number,
): number {
	if (raw === undefined || raw === "") return defaultValue;
	const n = Number.parseInt(raw, 10);
	if (!Number.isFinite(n) || !Number.isInteger(n)) {
		throw new Error(`${name} must be an integer (got ${JSON.stringify(raw)})`);
	}
	if (n < min || n > max) {
		throw new Error(`${name} must be between ${min} and ${max} (got ${n})`);
	}
	return n;
}

/**
 * Compute a stable endpoint_id for this watcher configuration.
 *
 * sha256(URL + "\n" + SECRET) truncated to 16 hex chars. Stable across
 * restarts with the same config. Distinct for two deployments pointing at
 * the same URL but with different secrets. Rotating either changes the id,
 * which a receiver can use to detect re-provisioning.
 */
export function computeEndpointId(url: string, secret: string): string {
	return createHash("sha256")
		.update(`${url}\n${secret}`)
		.digest("hex")
		.slice(0, 16);
}

export function loadDeliveryConfig(
	env: EnvLike = process.env,
): LoadedDeliveryConfig {
	const url = env.EVENT_WEBHOOK_URL?.trim();
	const secret = env.EVENT_WEBHOOK_SECRET?.trim();

	if (!url) {
		if (secret) {
			throw new Error(
				"EVENT_WEBHOOK_SECRET is set but EVENT_WEBHOOK_URL is not. " +
					"Either set both or neither.",
			);
		}
		return { enabled: false };
	}

	if (!secret) {
		throw new Error(
			"EVENT_WEBHOOK_URL is set but EVENT_WEBHOOK_SECRET is not. " +
				"Signed webhooks require a secret. Generate one with any secure random source.",
		);
	}

	let parsedUrl: URL;
	try {
		parsedUrl = new URL(url);
	} catch {
		throw new Error(
			`EVENT_WEBHOOK_URL is not a valid URL: ${JSON.stringify(url)}`,
		);
	}
	if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
		throw new Error(
			`EVENT_WEBHOOK_URL must be http:// or https:// (got ${parsedUrl.protocol})`,
		);
	}

	const timeoutMs = parseIntWithBounds(
		env.EVENT_WEBHOOK_TIMEOUT_MS,
		"EVENT_WEBHOOK_TIMEOUT_MS",
		DEFAULT_TIMEOUT_MS,
		1_000,
		120_000,
	);
	const downloadServerPort = parseIntWithBounds(
		env.DOWNLOAD_SERVER_PORT,
		"DOWNLOAD_SERVER_PORT",
		DEFAULT_PORT,
		1,
		65_535,
	);

	// When DOWNLOAD_BASE_URL isn't set, derive it from the (possibly
	// overridden) port so an operator flipping just DOWNLOAD_SERVER_PORT gets
	// download URLs that actually resolve.
	const downloadBaseUrl =
		env.DOWNLOAD_BASE_URL?.trim() || `http://localhost:${downloadServerPort}`;
	try {
		const parsedBase = new URL(downloadBaseUrl);
		if (parsedBase.protocol !== "http:" && parsedBase.protocol !== "https:") {
			throw new Error(
				`must be http:// or https:// (got ${parsedBase.protocol})`,
			);
		}
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		throw new Error(`DOWNLOAD_BASE_URL is not a valid URL: ${msg}`);
	}

	return {
		enabled: true,
		webhookUrl: url,
		webhookSecret: secret,
		timeoutMs,
		downloadServerPort,
		downloadBaseUrl: downloadBaseUrl.replace(/\/$/, ""),
		endpointId: computeEndpointId(url, secret),
	};
}
