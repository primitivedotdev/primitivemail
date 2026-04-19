# PrimitiveMail

A self-hosted SMTP inbox for agents. One command, one VPS, incoming mail on disk as JSON.

## Features

- **One command install.** Fresh Ubuntu VPS to working inbox in a few minutes.
- **Your domain, your IP, or a free `*.primitive.email` subdomain.** Bring DNS or skip it.
- **Email on disk as canonical JSON.** Tailable journal, per-email files, attachments bundled.
- **Pull or push.** `tail -f emails.jsonl`, or HMAC-signed webhooks to your endpoint.
- **Inbound auth built in.** SPF, DKIM, DMARC verification. Sender and recipient allowlists. Optional Spamhaus DNSBL.
- **Agent-scriptable installer.** `--no-prompt`, NDJSON progress on stdout, preflight check.

## Install

One-liner on a fresh Linux VPS with a public IPv4 and inbound TCP 25 reachable:

```bash
curl -fsSL https://get.primitive.dev | bash
```

Prefer to read the script before running it? Download, inspect, then execute:

```bash
curl -fsSL https://get.primitive.dev -o install.sh
less install.sh
bash install.sh
```

### Scripted install

For agents driving the install in a single pass:

```bash
curl -fsSL https://get.primitive.dev | bash -s -- \
  --no-prompt --json \
  --claim-subdomain \
  --event-webhook-url=https://your-endpoint
```

`--no-prompt` runs non-interactively. `--json` streams NDJSON progress events. `--claim-subdomain` grabs a free `*.primitive.email` name. `--event-webhook-url` wires push delivery. Run `curl -fsSL https://get.primitive.dev | bash -s -- --preflight` first to check RAM, disk, inbound 25, and outbound HTTPS.

### Verify your install

Once the installer finishes, send yourself a real external email to confirm the whole pipeline works:

```bash
primitive emails test
```

`primitive.dev` sends a test email to your claimed subdomain and the CLI waits for it to land in the local journal (default 30s). A successful run exercises DNS, inbound port 25, postfix, the watcher, and the journal writer in one call.

## Agent integration

See [AGENTS.md](./AGENTS.md) for the journal format, file layout, and webhook contract. Full docs at [primitive.dev/docs](https://primitive.dev/docs).

## License

MIT. Made by [primitive.dev](https://primitive.dev).
