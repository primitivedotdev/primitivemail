#!/usr/bin/env bash
# Wrapper to ensure environment variables are set before calling Python script
# Postfix pipe doesn't inherit environment, so we source from .env file

# Source environment from file (Postfix pipes don't inherit container env)
if [ -f /opt/mx-box/.env ]; then
  source /opt/mx-box/.env
fi

export WEBHOOK_URL="${WEBHOOK_URL}"
export WEBHOOK_SECRET="${WEBHOOK_SECRET}"
export LOKI_URL="${LOKI_URL:-}"
export LOKI_USER="${LOKI_USER:-}"
export LOKI_KEY="${LOKI_KEY:-}"

# Redirect stderr to stdout so Docker logs capture Python's logging output
exec /usr/bin/python3 /opt/mx-box/store_mail.py "$@" 2>&1
