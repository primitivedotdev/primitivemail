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
{"seq":1,"id":"20260312T203149Z-14f065f1","received_at":"2026-03-12T20:31:49Z","domain":"[203.0.113.10]","from":"\"Jane\" <jane@example.com>","from_address":"jane@example.com","to":"inbox@example.com","subject":"Hello","path":"[203.0.113.10]/20260312T203149Z-14f065f1.json","attachment_count":0}
```

- `seq` — monotonically increasing integer. Use this to resume after a crash.
- `from_address` — bare email address (no display name parsing needed).
- `path` — relative to `~/primitivemail/maildata/`. Read this file for full email content.

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

Response contract: plain 2xx on success. Any non-2xx (or network failure) is logged as a failed delivery in `deliveries.jsonl` — **no retries**. The journal (`emails.jsonl`) is the source of truth; if you need retry semantics, tail the journal and re-POST manually or write your own daemon. Redirects (3xx) are never followed; point `EVENT_WEBHOOK_URL` at the final destination.

Large emails (>256 KB) are not embedded inline. The payload's `email.content.download.url` points at the watcher's local download server (exposed on `DOWNLOAD_SERVER_PORT`, default 4001) and carries a 15-minute signed token. Fetching the URL is just `await fetch(event.email.content.download.url)` — no extra auth plumbing needed.

Backlog behavior: turning on `EVENT_WEBHOOK_URL` does NOT replay historical emails. Deliveries fire only for emails processed after the watcher restarts. To replay history, iterate `emails.jsonl` yourself.

Every delivery outcome is logged to `~/primitivemail/maildata/deliveries.jsonl`. Rotate it yourself (logrotate / scripts) if your volume warrants it.

### Optional env vars

| Variable | Default | Purpose |
|---|---|---|
| `EVENT_WEBHOOK_TIMEOUT_MS` | `10000` | Per-request timeout |
| `DOWNLOAD_SERVER_PORT` | `4001` | Port the watcher binds its download server to |
| `DOWNLOAD_BASE_URL` | `http://localhost:4001` | Base URL embedded in `download.url`. Override in sibling-container topologies to e.g. `http://watcher:4001` |

## CLI Commands

```bash
primitive version          # Show version
primitive emails-status    # Count emails, show latest sender/time
primitive restart          # Reload config (only restarts changed containers)
```

## Configuration

Config file: `~/primitivemail/.env`

Key settings:
- `ALLOWED_SENDER_DOMAINS` — comma-separated domains allowed to send (blank = anyone)
- `ALLOWED_SENDERS` — comma-separated email addresses allowed to send
- `ALLOWED_RECIPIENTS` — comma-separated addresses that can receive (blank = any)
- `SPOOF_PROTECTION` — `off`, `monitor`, `standard`, or `strict`

After editing `.env`, run `primitive restart` to apply changes.

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
  .env                                    # configuration
  docker-compose.yml                      # service definitions
```
