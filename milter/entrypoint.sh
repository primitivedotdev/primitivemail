#!/usr/bin/env bash
set -euo pipefail

MYHOSTNAME="${MYHOSTNAME:-localhost}"
MYDOMAIN="${MYDOMAIN:-localhost}"
export MYHOSTNAME MYDOMAIN

# Default self-signed paths. Used both as the fallback when TLS_CERT/TLS_KEY
# are unset and as the recovery target if a custom path is configured but
# missing at startup (e.g. Let's Encrypt issuance has not run yet, or the
# /etc/letsencrypt mount is not present).
DEFAULT_TLS_CERT="/etc/postfix/tls/server.pem"
DEFAULT_TLS_KEY="/etc/postfix/tls/server.key"

TLS_CERT="${TLS_CERT:-$DEFAULT_TLS_CERT}"
TLS_KEY="${TLS_KEY:-$DEFAULT_TLS_KEY}"

# Defensive fallback: if a custom TLS_CERT was configured but the file is not
# on disk, log a clear warning and fall back to the self-signed default rather
# than crashing the container. The cert key is checked alongside the cert so
# half-configured pairs do not silently load only one side.
if [[ "$TLS_CERT" != "$DEFAULT_TLS_CERT" ]]; then
    if [[ ! -f "$TLS_CERT" || ! -f "$TLS_KEY" ]]; then
        echo "WARNING: TLS_CERT=${TLS_CERT} or TLS_KEY=${TLS_KEY} not found on disk." 1>&2
        echo "WARNING: Falling back to self-signed certificate at ${DEFAULT_TLS_CERT}." 1>&2
        echo "WARNING: This is usually transient (Let's Encrypt issuance pending, or volume mount missing)." 1>&2
        TLS_CERT="$DEFAULT_TLS_CERT"
        TLS_KEY="$DEFAULT_TLS_KEY"
    fi
fi

# Generate self-signed TLS cert at the default path if none exists.
# Always done at the default location so the fallback above has something
# to land on, even when TLS_CERT was set to a custom path.
if [[ ! -f "$DEFAULT_TLS_CERT" ]]; then
    mkdir -p /etc/postfix/tls
    openssl req -new -x509 -days 3650 -nodes \
        -out "$DEFAULT_TLS_CERT" \
        -keyout "$DEFAULT_TLS_KEY" \
        -subj "/CN=${MYHOSTNAME}" 2>/dev/null
    chmod 600 "$DEFAULT_TLS_KEY"
    echo "Generated self-signed TLS certificate for ${MYHOSTNAME}"
fi

# Render postfix main.cf
envsubst '$MYHOSTNAME $MYDOMAIN' < /opt/mx-box/postfix-main.cf.template > /etc/postfix/main.cf

# Propagate TLS_CERT/TLS_KEY into Postfix. The template hardcodes the default
# self-signed paths so the no-env-set case keeps working unchanged; postconf
# overrides them when a caller has configured custom paths (or after the
# fallback above).
postconf -e "smtpd_tls_cert_file=${TLS_CERT}" "smtpd_tls_key_file=${TLS_KEY}"

# Enable IP literal support (receive mail at user@[1.2.3.4] without DNS)
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

# Append custom transport to master.cf
cat /opt/mx-box/postfix-master.cf.append >> /etc/postfix/master.cf

# Copy relay configuration (accept any domain)
cp /opt/mx-box/relay_domains /etc/postfix/relay_domains
cp /opt/mx-box/relay_recipients /etc/postfix/relay_recipients
cp /opt/mx-box/command_filter.pcre /etc/postfix/command_filter.pcre

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

# Ensure Postfix queue directories exist and are readable
# (host mounts may start empty; permissions needed for monitoring tools)
for dir in incoming active deferred hold maildrop corrupt bounce defer flush saved trace; do
    mkdir -p "/var/spool/postfix/$dir"
done
chmod 755 /var/spool/postfix/incoming /var/spool/postfix/active /var/spool/postfix/deferred /var/spool/postfix/hold
chown -R postfix:postfix /var/spool/postfix

# Datadog APM tracing (optional — set DATADOG_TRACING_ENABLED=true to enable)
if [ "${DATADOG_TRACING_ENABLED:-false}" = "true" ]; then
    export DD_SERVICE="${DD_SERVICE:-milter}"
    export DD_ENV="${DD_ENV:-unknown}"
    export DD_TRACE_AGENT_URL="${DD_TRACE_AGENT_URL:-http://localhost:8126}"
    export DD_TRACE_PROPAGATION_STYLE="${DD_TRACE_PROPAGATION_STYLE:-datadog,tracecontext}"
    echo "Datadog tracing enabled (service=${DD_SERVICE}, env=${DD_ENV})"
fi

# Start the milter in background (MUST be running before Postfix starts)
echo "Starting milter..."
/opt/mx-box/primitivemail_milter.py &
MILTER_PID=$!

# Wait for milter to be ready (check if socket is listening)
for i in {1..10}; do
    if netstat -tln 2>/dev/null | grep -q ':9900 ' || ss -tln 2>/dev/null | grep -q ':9900 '; then
        echo "Milter is ready on port 9900"
        break
    fi
    if ! kill -0 $MILTER_PID 2>/dev/null; then
        echo "ERROR: Milter process died!"
        exit 1
    fi
    echo "Waiting for milter to start... ($i/10)"
    sleep 1
done

# Verify milter is still running
if ! kill -0 $MILTER_PID 2>/dev/null; then
    echo "ERROR: Milter process is not running!"
    exit 1
fi

echo "Milter started with PID $MILTER_PID"

# Graceful shutdown handler — drain Postfix queue, then stop milter
shutdown() {
    echo "Received shutdown signal, draining..."
    /usr/sbin/postfix flush 2>/dev/null
    /usr/sbin/postfix stop 2>/dev/null
    kill "$MILTER_PID" 2>/dev/null
    # Wait for milter to exit (up to 10s)
    for i in {1..10}; do
        kill -0 "$MILTER_PID" 2>/dev/null || break
        sleep 1
    done
    echo "Shutdown complete"
    exit 0
}

trap shutdown SIGTERM SIGINT

# Start Postfix in foreground
/usr/sbin/postfix start-fg &
POSTFIX_PID=$!

# Wait for Postfix — if it exits on its own, we exit too
wait $POSTFIX_PID
