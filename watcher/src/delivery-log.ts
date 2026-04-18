/**
 * Delivery log: one line per final delivery outcome.
 *
 * Appended to `maildata/deliveries.jsonl`. Rotates at ~100 MB to
 * `deliveries.jsonl.1` (overwriting any prior .1). Single rotation level
 * only — we're not reimplementing logrotate.
 */

import { appendFile, rename, stat } from "node:fs/promises";

export const DELIVERY_LOG_SOFT_CAP_BYTES = 100 * 1024 * 1024;

export interface DeliveryLogEntry {
	seq: number;
	id: string;
	domain: string;
	url_hash: string;
	attempts: number;
	status: string;
	confirmed?: boolean;
	last_error?: string | null;
	status_code?: number | null;
	last_attempt_at: string;
	duration_ms?: number;
}

let appendCountSinceLastCheck = 0;
const ROTATION_CHECK_INTERVAL = 1_000;

/**
 * Append one JSON line. Checks size every ROTATION_CHECK_INTERVAL appends;
 * rotates when the soft cap is crossed.
 */
export async function appendDeliveryLog(
	path: string,
	entry: DeliveryLogEntry,
): Promise<void> {
	const line = `${JSON.stringify(entry)}\n`;
	await appendFile(path, line);
	appendCountSinceLastCheck += 1;
	if (appendCountSinceLastCheck >= ROTATION_CHECK_INTERVAL) {
		appendCountSinceLastCheck = 0;
		await maybeRotate(path);
	}
}

/**
 * If the log has crossed the soft cap, rotate it to `<path>.1` and truncate.
 * Exposed for tests that want to force the check; normally gated by the
 * append counter.
 */
export async function maybeRotate(path: string): Promise<boolean> {
	const st = await stat(path).catch(() => null);
	if (!st || st.size < DELIVERY_LOG_SOFT_CAP_BYTES) return false;
	const rotated = `${path}.1`;
	await rename(path, rotated);
	console.warn(
		`[delivery-log] rotated ${path} -> ${rotated} at ${st.size} bytes`,
	);
	return true;
}

/** Test-only: reset the rotation check counter. */
export function __resetRotationCounterForTests(): void {
	appendCountSinceLastCheck = 0;
}
