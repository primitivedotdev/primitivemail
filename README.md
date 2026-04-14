# PrimitiveMail

Self-hosted mail server for receiving email at any address on your domain or IP.

## What it does

- Accepts inbound SMTP mail on port `25`
- Stores messages in `maildata/` as raw `.eml`, parsed JSON, and metadata
- Optionally forwards emails to a webhook
- Supports sender and recipient allowlists
- Supports SPF, DKIM, and DMARC-based spoof protection
- Includes a small CLI for status checks and reloads

## Quick start

1. Copy the example config:

```bash
cp .env.example .env
```

2. Set at least `MYHOSTNAME` and `MYDOMAIN` in `.env`.

3. Start the services:

```bash
docker compose up -d --build
```

4. Point your MX record at the host running PrimitiveMail and make sure TCP port `25` is reachable.

## Common configuration

- `MYHOSTNAME`: Mail server hostname such as `mx.example.com`
- `MYDOMAIN`: Domain to receive mail for
- `ENABLE_IP_LITERAL` and `IP_LITERAL`: Accept mail for `user@[IP]`
- `WEBHOOK_URL` and `WEBHOOK_SECRET`: Forward parsed mail to an application
- `ALLOWED_SENDER_DOMAINS` and `ALLOWED_SENDERS`: Restrict who can send mail in
- `ALLOWED_RECIPIENTS`: Restrict which inboxes can receive mail
- `SPOOF_PROTECTION`: `off`, `monitor`, `standard`, or `strict`
- `MAIL_DIR`: Override the standalone mail storage directory

See `.env.example` for the full configuration surface.

## Mail storage

PrimitiveMail stores incoming mail under `maildata/`.

- `maildata/emails.jsonl`: append-only journal for new mail notifications
- `maildata/<domain>/<id>.json`: parsed email, headers, auth results, and attachment metadata
- `maildata/<domain>/<id>.eml`: raw email source
- `maildata/<domain>/<id>.attachments.tar.gz`: bundled attachments when present

## CLI

The repository includes a small management CLI:

```bash
python3 cli/primitive version
python3 cli/primitive emails-status
python3 cli/primitive restart
```

## Development

Run the test suite with:

```bash
make test
```
