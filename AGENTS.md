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

## Webhooks

When `WEBHOOK_URL` is set, the milter POSTs each accepted delivery to that URL. Headers:

- `webhook-id` — per-delivery idempotency key. Stable across Postfix retries of the same delivery. Distinct for different recipients of the same message.
- `webhook-timestamp` — Unix seconds. The SDK verifier accepts a 5-minute window by default.
- `webhook-signature` — Standard Webhooks HMAC: `v1,<base64>`.
- `primitive-signature` — legacy Stripe-style header for older SDK consumers: `t=<ts>,v1=<hex>`.
- `Authorization: Bearer <WEBHOOK_SECRET>` — opt-in only via `EMIT_LEGACY_BEARER=true`. Off by default in v0.4 because it transmits the HMAC signing secret; any receiver that logs headers would expose the secret and enable signature forgery. Removed in v0.5.

Verify with `@primitivedotdev/sdk/webhook` (Node) or `from primitive import handle_webhook` (Python). Do not reimplement the verification; both signers are tested against shared cross-language fixtures.

`webhook-id` is derived as `uuid.uuid5(ns, f"{message_id}:{recipient}:{queue_id}")` where `ns = 6f79e4a8-a494-4f7e-9124-90d94cb26d5d` (published here so operators can reproduce a value by hand) and `queue_id` is the Postfix queue id. Same recipient, same queue id produces the same `webhook-id` on retry. Different recipient or different queue id produces a different `webhook-id`. Receivers MUST deduplicate on `webhook-id`.

`WEBHOOK_SECRET` must be a base64-encoded value, optionally prefixed with `whsec_`. The milter refuses to start otherwise. Rotate with `python3 -c "import os,base64; print('whsec_' + base64.b64encode(os.urandom(32)).decode())"`.

## File Layout

```
~/primitivemail/
  maildata/
    emails.jsonl                          # journal (append-only)
    <domain>/
      <id>.eml                            # raw email
      <id>.meta.json                      # SMTP envelope + auth data
      <id>.json                           # canonical parsed email
      <id>.attachments.tar.gz             # attachment bundle (if any)
  .env                                    # configuration
  docker-compose.yml                      # service definitions
```
