#!/usr/bin/env bash
set -euo pipefail

MYHOSTNAME="${MYHOSTNAME:-localhost}"
MYDOMAIN="${MYDOMAIN:-localhost}"
export MYHOSTNAME MYDOMAIN
SERVICE_ROLE="${SERVICE_ROLE:-postfix}"
MILTER_ENDPOINT="${MILTER_ENDPOINT:-milter:9900}"
export MILTER_ENDPOINT

render_postfix() {
    TLS_CERT="${TLS_CERT:-/etc/postfix/tls/server.pem}"
    TLS_KEY="${TLS_KEY:-/etc/postfix/tls/server.key}"
    if [[ ! -f "$TLS_CERT" ]]; then
        mkdir -p /etc/postfix/tls
        openssl req -new -x509 -days 3650 -nodes \
            -out "$TLS_CERT" \
            -keyout "$TLS_KEY" \
            -subj "/CN=${MYHOSTNAME}" 2>/dev/null
        chmod 600 "$TLS_KEY"
        echo "Generated self-signed TLS certificate for ${MYHOSTNAME}"
    fi

    envsubst '$MYHOSTNAME $MYDOMAIN $MILTER_ENDPOINT' < /opt/mx-box/postfix-main.cf.template > /etc/postfix/main.cf

    if [[ "${ENABLE_IP_LITERAL:-false}" == "true" && -n "${IP_LITERAL:-}" ]]; then
        echo "Enabling IP literal support for [${IP_LITERAL}]"
        postconf -e "mydestination = [${IP_LITERAL}], localhost"
        postconf -e "resolve_numeric_domain = yes"
        postconf -e "smtpd_command_filter = pcre:/etc/postfix/command_filter.pcre"
    fi

    # Extend mynetworks with additional trusted CIDRs (e.g., load gen subnet for staging)
    if [[ -n "${MYNETWORKS_EXTRA:-}" ]]; then
        postconf -e "mynetworks = 127.0.0.0/8 ${MYNETWORKS_EXTRA}"
        echo "Extended mynetworks with: ${MYNETWORKS_EXTRA}"
    fi

    cat /opt/mx-box/postfix-master.cf.append >> /etc/postfix/master.cf

    cp /opt/mx-box/relay_domains /etc/postfix/relay_domains
    cp /opt/mx-box/relay_recipients /etc/postfix/relay_recipients
    cp /opt/mx-box/command_filter.pcre /etc/postfix/command_filter.pcre

    for dir in incoming active deferred hold maildrop corrupt bounce defer flush saved trace; do
        mkdir -p "/var/spool/postfix/$dir"
    done
    chmod 755 /var/spool/postfix/incoming /var/spool/postfix/active /var/spool/postfix/deferred /var/spool/postfix/hold
    chown -R postfix:postfix /var/spool/postfix
}

# Create .env file for config (Postfix pipes don't inherit container env)
cat > /opt/mx-box/.env <<EOF
WEBHOOK_URL=${WEBHOOK_URL:-}
WEBHOOK_SECRET=${WEBHOOK_SECRET:-}
STORAGE_URL=${STORAGE_URL:-}
STORAGE_KEY=${STORAGE_KEY:-}
STORAGE_AUTH_STYLE=${STORAGE_AUTH_STYLE:-s3}
MYDOMAIN=${MYDOMAIN:-primitivemail}
MAIL_DIR=${MAIL_DIR:-/mail/incoming}
ALLOWED_SENDER_DOMAINS=${ALLOWED_SENDER_DOMAINS:-}
ALLOWED_SENDERS=${ALLOWED_SENDERS:-}
ALLOW_BOUNCES=${ALLOW_BOUNCES:-true}
ALLOWED_RECIPIENTS=${ALLOWED_RECIPIENTS:-}
SPOOF_PROTECTION=${SPOOF_PROTECTION:-off}
EOF

# Copy and compile aliases (using luser_relay, not transport_maps)
cp /opt/mx-box/aliases /etc/aliases
newaliases

# Ensure script is executable
chmod +x /opt/mx-box/store_mail.py

# Fix permissions on mail directories
find /mail/incoming -type d -exec chmod 755 {} \; 2>/dev/null || true

# Clean up old debug logs (legacy, no longer created with non-debug wrapper)
find /tmp -name 'pipe-debug-*.log' -mtime +1 -delete 2>/dev/null || true

# Start rsyslog (optional, for logs)
service rsyslog start || true

# Optionally tail Postfix log to stdout for container log collectors (Datadog, CloudWatch, etc.)
# Postfix still writes to /var/log/postfix.log regardless — this just mirrors it to stdout.
if [ "${POSTFIX_LOG_STDOUT:-false}" = "true" ]; then
    touch /var/log/postfix.log
    tail -F /var/log/postfix.log &
    echo "Postfix log tailing to stdout enabled"
fi

# Datadog APM tracing (optional — set DATADOG_TRACING_ENABLED=true to enable)
if [ "${DATADOG_TRACING_ENABLED:-false}" = "true" ]; then
    export DD_SERVICE="${DD_SERVICE:-milter}"
    export DD_ENV="${DD_ENV:-unknown}"
    export DD_TRACE_AGENT_URL="${DD_TRACE_AGENT_URL:-http://localhost:8126}"
    export DD_TRACE_PROPAGATION_STYLE="${DD_TRACE_PROPAGATION_STYLE:-datadog,tracecontext}"
    echo "Datadog tracing enabled (service=${DD_SERVICE}, env=${DD_ENV})"
fi

case "$SERVICE_ROLE" in
  postfix)
    render_postfix
    exec /usr/sbin/postfix start-fg
    ;;
  milter)
    exec /opt/mx-box/primitivemail_milter.py
    ;;
  *)
    echo "ERROR: unsupported SERVICE_ROLE '$SERVICE_ROLE' (expected 'postfix' or 'milter')"
    exit 1
    ;;
esac
