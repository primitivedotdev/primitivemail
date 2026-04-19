# PrimitiveMail Agent Integration

Self-hosted mail server. Receive email at any address on your domain or IP.

## Quick Start

Emails are stored as JSON files. A journal file tracks all incoming email.

### Journal (new email notifications)

```
~/primitivemail/maildata/emails.jsonl
```

Each line is a JSON object:

```json
{"seq":1,"id":"20260312T203149Z-14f065f1","received_at":"2026-03-12T20:31:49Z","domain":"[203.0.113.10]","from":"\"Jane\" <jane@example.com>","from_address":"jane@example.com","to":"inbox@example.com","subject":"Hello","path":"[203.0.113.10]/20260312T203149Z-14f065f1.json","attachment_count":1,"attachment_names":["report.pdf"]}
```

- `seq` is a monotonically increasing integer. Use this to resume after a crash.
- `from_address` is the bare email address (no display name parsing needed).
- `path` is relative to `~/primitivemail/maildata/`. Read this file for full email content.
- `attachment_names` is a flat list, one slot per downloadable attachment, in MIME tree order. Lets routers decide whether to fetch the full per-email JSON without a second read. Empty array when `attachment_count` is 0. A slot may be `null` if the MIME part lacked a filename; fall back to the full JSON for `content_type` or `id` in that case.

### Full Email JSON

```
~/primitivemail/maildata/<domain>/<id>.json
```

Contains: headers, parsed body (text + HTML), SMTP envelope, attachments metadata, auth results (SPF/DKIM/DMARC), raw .eml path, SHA-256 hash.

### Attachments

If `attachment_count > 0`, attachments are bundled in:

```
~/primitivemail/maildata/<domain>/<id>.attachments.tar.gz
```

Each attachment entry in the JSON has `filename`, `content_type`, `size_bytes`, `sha256`, and `tar_path` (path within the archive).

## Consuming Email

### Watch for new email (recommended)

```bash
tail -f ~/primitivemail/maildata/emails.jsonl
```

### Resume after crash

Save the last `seq` you processed. On restart, skip lines until `seq > last_seq`.

```bash
# Read from seq 5 onward
tail -n +1 ~/primitivemail/maildata/emails.jsonl | while read -r line; do
  seq=$(echo "$line" | jq -r '.seq // 0')
  [ "$seq" -le 4 ] && continue
  # process $line
done
```

### Read a specific email

```bash
cat ~/primitivemail/maildata/<path from journal line>
```

## Receiving webhooks

Two consumption models, pick one.

**Pull** (`tail -f emails.jsonl`, above) is the default and works with zero config.

**Push** — new email triggers a signed HTTP POST to a URL you control. Set two env vars in your `~/primitivemail/.env` and `primitive restart`:

```
EVENT_WEBHOOK_URL=http://host.docker.internal:3000/hook   # dev: receiver runs on host
EVENT_WEBHOOK_SECRET=<random-64-hex>                       # HMAC signing key
```

The watcher signs each payload with HMAC-SHA256 and POSTs it to your URL. The payload is byte-identical to what managed Primitive produces — verify it with `@primitivedotdev/sdk`'s `handleWebhook`. The **raw request body** is what's signed; use `express.raw({ type: "application/json" })`, NOT `express.json()`, or the signature won't verify.

Minimal Express receiver:

```js
const express = require("express");
const { handleWebhook, PrimitiveWebhookError } = require("@primitivedotdev/sdk");

const app = express();
app.post("/hook", express.raw({ type: "application/json" }), (req, res) => {
	try {
		const event = handleWebhook({
			body: req.body,
			headers: req.headers,
			secret: process.env.EVENT_WEBHOOK_SECRET,
		});
		console.log("received:", event.email.headers.from, event.email.headers.subject);
		res.status(200).send();
	} catch (err) {
		if (err instanceof PrimitiveWebhookError) return res.status(400).send(err.code);
		res.status(500).send();
	}
});

app.listen(3000);
```

Response contract: plain 2xx on success. Any non-2xx (or network failure) is logged as a failed delivery in `deliveries.jsonl` — **no retries**. Redirects (3xx) are never followed; point `EVENT_WEBHOOK_URL` at the final destination.

**What the journal preserves (and what it doesn't).** `emails.jsonl` is the source of truth for the **email** — envelope, headers, body, attachments. It's not a record of the signed wire payload we POSTed. If you want to re-deliver a failed event, don't copy the failure line and expect to replay the exact same bytes — signatures are timestamped, download URLs carry 15-minute tokens that have long since expired. Instead: look up the email by `id` in the journal, regenerate the event with a tool that calls `buildEventFromParsedData` from `@primitivedotdev/sdk/contract`, sign it with your `EVENT_WEBHOOK_SECRET`, POST it. A `primitive replay <id>` CLI that does exactly this is on the roadmap.

Large emails (>256 KB) are not embedded inline. The payload's `email.content.download.url` points at the watcher's local download server (exposed on `DOWNLOAD_SERVER_PORT`, default 4001) and carries a 15-minute signed token. Fetching the URL is just `await fetch(event.email.content.download.url)` — no extra auth plumbing needed.

Backlog behavior: turning on `EVENT_WEBHOOK_URL` does NOT replay historical emails. Deliveries fire only for emails processed after the watcher restarts. To replay history, iterate `emails.jsonl` yourself.

Every completed delivery is logged to `~/primitivemail/maildata/deliveries.jsonl`. Rotate it yourself (logrotate / scripts) if your volume warrants it.

**Shutdown gap.** If the watcher receives SIGTERM while a delivery is in flight, it has a 3-second grace window to finish; anything still running after that is abandoned without a log line. A journal entry in `emails.jsonl` without a corresponding row in `deliveries.jsonl` therefore means "status unknown" — either the delivery is still in-progress (check back in a moment) or it was cut short by a restart. The journal is authoritative; re-post from the journal if you need guaranteed delivery.

**Endpoint ID rotation.** Each event carries `delivery.endpoint_id` derived from `sha256(EVENT_WEBHOOK_URL + EVENT_WEBHOOK_SECRET)`. Changing either value changes the ID — receivers doing idempotency keyed on `endpoint_id` will see a rotated deployment as a new endpoint. Plan secret rotations accordingly.

**Migrating between self-host and managed Primitive.** Receiver code that verifies with `handleWebhook({ body, headers, secret })` works identically against both — zero changes. Three gotchas if your receiver does anything beyond that:

1. If you hardcoded the download-URL origin (e.g. in a CSP, allowlist, or link-rewriter), the origin flips from `http://localhost:4001/...` (self-host) to an HTTPS managed origin. Use `event.email.content.download.url` verbatim instead.
2. If you use `delivery.endpoint_id` as an idempotency key, expect every event to look like a new endpoint after cutover — same root cause as rotation above.
3. If you're verifying download URLs off-band with `verifyDownloadToken`, the audience is `"primitive:raw-download"` / `"primitive:attachments-download"` on both products as of SDK 0.5.1.

**TLS for self-signed or internal CAs.** The watcher's outbound fetch uses Node's default TLS. If your receiver is behind a corporate/internal CA that Node doesn't trust out of the box, set `NODE_EXTRA_CA_CERTS=/path/to/ca.pem` in the watcher container's environment and mount the CA bundle in. Example addition to `docker-compose.yml`:

```yaml
watcher:
  environment:
    NODE_EXTRA_CA_CERTS: /etc/ssl/certs/my-ca.pem
  volumes:
    - ./my-ca.pem:/etc/ssl/certs/my-ca.pem:ro
```

Without this, TLS failures appear in `deliveries.jsonl` as `fetch failed: self-signed certificate in certificate chain` / `unable to verify the first certificate`. No in-app escape hatch is provided — this is the right lever.

### Optional env vars

| Variable | Default | Purpose |
|---|---|---|
| `EVENT_WEBHOOK_TIMEOUT_MS` | `10000` | Per-request timeout |
| `DOWNLOAD_SERVER_PORT` | `4001` | Port the watcher binds its download server to |
| `DOWNLOAD_BASE_URL` | `http://localhost:4001` | Base URL embedded in `download.url`. Override in sibling-container topologies to e.g. `http://watcher:4001` |

## CLI Commands

```bash
primitive version                  # Show version
primitive emails status            # Count emails, show latest sender/time
primitive emails list [opts]       # List recent emails from the journal
primitive emails read <id> [opts]  # Read one email in json, raw, text, or html
primitive emails since <seq>       # Stream journal entries with seq > <seq>
primitive emails count [opts]      # Count matching emails
primitive restart                  # Reload config (only restarts changed containers)
```

`primitive emails-status` is kept as a hidden alias of `primitive emails status` for one release. It prints a deprecation notice and forwards. Migrate scripts to the `noun verb` form.

## Configuration

Config file: `~/primitivemail/.env`

Key settings:
- `ALLOWED_SENDER_DOMAINS` — comma-separated domains allowed to send (blank = anyone)
- `ALLOWED_SENDERS` — comma-separated email addresses allowed to send
- `ALLOWED_RECIPIENTS` — comma-separated addresses that can receive (blank = any)
- `SPOOF_PROTECTION` — `off`, `monitor`, `standard`, or `strict`

After editing `.env`, run `primitive restart` to apply changes.

### Observability (optional)

The Prometheus exporter (`postfix-exporter`) and log forwarder (Grafana Alloy) are off by default. To enable them, set `COMPOSE_PROFILES=observability` in `.env` and run `primitive restart`. Configure `PROMETHEUS_URL` / `PROMETHEUS_USER` / `PROMETHEUS_KEY` to point at your Prometheus-compatible endpoint.

## File Layout

```
~/primitivemail/
  maildata/
    emails.jsonl                          # journal (append-only)
    deliveries.jsonl                      # webhook delivery outcomes (only when push is enabled)
    <domain>/
      <id>.eml                            # raw email
      <id>.meta.json                      # SMTP envelope + auth data
      <id>.json                           # canonical parsed email
      <id>.attachments.tar.gz             # attachment bundle (if any)
      <id>.meta.json.failed               # watcher poison marker (errored during parse)
  .env                                    # configuration
  docker-compose.yml                      # service definitions
```

`<id>.meta.json.failed` is a watcher-internal poison marker. Agents MUST NOT match it in their own globs and MUST NOT touch it. The journal is the source of truth for which ids exist; a file whose presence the journal does not announce should be treated as watcher state and left alone.
