# PrimitiveMail

A self-hosted SMTP inbox for agents. One command, one VPS, incoming mail on disk as JSON.

Landing page: [primitive.dev/mail](https://primitive.dev/mail).

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

Want to pin a checksum? `get.primitive.dev` publishes a `sha256sum`-compatible hash alongside every served `install.sh`. They are generated from the same response body, so the hash matches whatever bytes you would have downloaded:

```bash
curl -fsSL https://get.primitive.dev -o install.sh && \
  curl -fsSL https://get.primitive.dev/install.sh.sha256 | sha256sum -c && \
  bash install.sh
```

The `&&` chain is load-bearing: if `sha256sum -c` exits non-zero (hash mismatch, network error, or a corrupted `.sha256` response), `bash install.sh` never runs. For branch-served installs (`get.primitive.dev/<branch>`), fetch `get.primitive.dev/<branch>/install.sh.sha256` instead.

### Scripted install

For agents driving the install in a single pass:

```bash
curl -fsSL https://get.primitive.dev | bash -s -- \
  --no-prompt --json \
  --claim-subdomain \
  --event-webhook-url=https://your-endpoint
```

`--no-prompt` runs non-interactively. `--json` streams NDJSON progress events on stdout, with human-readable progress on stderr. Redirect them separately (`>events.ndjson 2>install.log`) if you want stdout to parse cleanly with `jq`. `--claim-subdomain` grabs a free `*.primitive.email` name. `--event-webhook-url` wires push delivery. Run `curl -fsSL https://get.primitive.dev | bash -s -- --preflight` first to check RAM, disk, inbound 25, and outbound HTTPS.

### Verify your install

Once the installer finishes, send yourself a real external email to confirm the whole pipeline works:

```bash
primitive emails test
```

`primitive.dev` sends a test email to your claimed subdomain and the CLI waits for it to land in the local journal (default 30s). A successful run exercises DNS, inbound port 25, postfix, the watcher, and the journal writer in one call.

## Running on AWS (EC2, Lightsail)

PrimitiveMail works fine on AWS for its stated use case. Two things to know:

- **Attach an Elastic IP before publishing any address.** A claimed `*.primitive.email` subdomain is anchored to the instance's current public IPv4. Instance stop/start without an Elastic IP rotates the public IP and silently detaches the subdomain; a new install on the new IP gets a different name.
- **EC2 and Lightsail block outbound TCP 25 by default.** This does not affect inbound mail (PrimitiveMail is inbound-only by design), so the receive pipeline works out of the box. It matters only if you later want to send from the same box: AWS requires a [port 25 removal request](https://aws.amazon.com/premiumsupport/knowledge-center/ec2-port-25-throttle/), or you use a relay.

## Agent integration

See [AGENTS.md](./AGENTS.md) for the journal format, file layout, and webhook contract. Full docs at [primitive.dev/docs](https://primitive.dev/docs).

## License

MIT. Made by [primitive.dev](https://primitive.dev).
