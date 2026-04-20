#!/usr/bin/env bash
set -euo pipefail

# Read email from stdin
EMAIL_CONTENT=$(cat)

# Extract metadata from email headers (|| true prevents grep failures from killing script)
RECIPIENT=$(echo "$EMAIL_CONTENT" | grep -i "^X-Original-To:" | head -1 | sed 's/^X-Original-To: *//i' | tr -d '\r' || true)

# Fallback to argument if X-Original-To not found
if [ -z "$RECIPIENT" ] && [ -n "${1:-}" ]; then
  RECIPIENT="$1"
fi

# If still empty, try other headers
if [ -z "$RECIPIENT" ]; then
  RECIPIENT=$(echo "$EMAIL_CONTENT" | grep -i "^To:" | head -1 | sed 's/^To: *//i' | tr -d '\r' | sed 's/.*<\(.*\)>.*/\1/' || true)
fi

SENDER=$(echo "$EMAIL_CONTENT" | grep -i "^From:" | head -1 | sed 's/^From: *//i' | tr -d '\r' || true)
SUBJECT=$(echo "$EMAIL_CONTENT" | grep -i "^Subject:" | head -1 | sed 's/^Subject: *//i' | tr -d '\r' || true)
MESSAGE_ID=$(echo "$EMAIL_CONTENT" | grep -i "^Message-ID:" | head -1 | sed 's/^Message-ID: *//i' | tr -d '\r' || true)
SIZE=$(echo -n "$EMAIL_CONTENT" | wc -c | tr -d ' ')
DOMAIN=$(echo "$RECIPIENT" | cut -d@ -f2)

echo "[store-mail.sh] ================================================" >&2
echo "[store-mail.sh] Received email for: $RECIPIENT" >&2
echo "[store-mail.sh] From: $SENDER" >&2
echo "[store-mail.sh] Subject: $SUBJECT" >&2
echo "[store-mail.sh] Size: $SIZE bytes" >&2
echo "[store-mail.sh] Domain: $DOMAIN" >&2

# Save to disk as backup
BACKUP_DIR="/mail/incoming/${DOMAIN}"
mkdir -p "$BACKUP_DIR"
TS=$(date -u +"%Y%m%dT%H%M%SZ")
RANDOM_ID=$(tr -dc A-Za-z0-9 </dev/urandom | head -c 8 || true)
FILENAME="${TS}-${RANDOM_ID}.eml"
echo "$EMAIL_CONTENT" > "${BACKUP_DIR}/${FILENAME}"

echo "[store-mail.sh] Saved to disk: ${BACKUP_DIR}/${FILENAME}" >&2

# Call webhook (if configured)
if [ -n "${WEBHOOK_URL:-}" ] && [ -n "${WEBHOOK_SECRET:-}" ]; then
  echo "[store-mail.sh] Webhook enabled, preparing payload..." >&2

  # Base64 encode the email
  EML_BASE64=$(echo "$EMAIL_CONTENT" | base64 -w 0)

  echo "[store-mail.sh] Posting to webhook: ${WEBHOOK_URL}" >&2

  # POST to webhook with JSON payload
  HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/webhook-response.txt \
    -X POST "${WEBHOOK_URL}" \
    -H "Authorization: Bearer ${WEBHOOK_SECRET}" \
    -H "Content-Type: application/json" \
    -d "$(jq -n \
      --arg recipient "$RECIPIENT" \
      --arg sender "$SENDER" \
      --arg subject "$SUBJECT" \
      --arg message_id "$MESSAGE_ID" \
      --arg domain "$DOMAIN" \
      --argjson size "$SIZE" \
      --arg eml "$EML_BASE64" \
      '{recipient: $recipient, sender: $sender, subject: $subject, message_id: $message_id, domain: $domain, size: $size, eml_base64: $eml}')" \
    || echo "000")

  echo "[store-mail.sh] Webhook response code: $HTTP_CODE" >&2

  if [ "$HTTP_CODE" = "200" ]; then
    WEBHOOK_RESPONSE=$(cat /tmp/webhook-response.txt)
    echo "[store-mail.sh] Webhook success: $WEBHOOK_RESPONSE" >&2
  else
    WEBHOOK_ERROR=$(cat /tmp/webhook-response.txt)
    echo "[store-mail.sh] Webhook failed: $WEBHOOK_ERROR" >&2
  fi

  rm -f /tmp/webhook-response.txt
else
  echo "[store-mail.sh] Webhook not configured (WEBHOOK_URL or WEBHOOK_SECRET missing)" >&2
fi

echo "[store-mail.sh] ================================================" >&2

exit 0
