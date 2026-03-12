#!/usr/bin/env bash
# Debug wrapper - logs everything to file

LOGFILE="/tmp/pipe-debug-$(date +%s).log"

{
  echo "=== Wrapper called at $(date) ==="
  echo "Args: $@"
  echo "User: $(whoami)"
  echo "PWD: $(pwd)"

  # Source environment from file (Postfix pipes don't inherit container env)
  if [ -f /opt/mx-box/.env ]; then
    source /opt/mx-box/.env
    echo "Loaded env from /opt/mx-box/.env"
  fi

  echo "WEBHOOK_URL: ${WEBHOOK_URL:-NOT SET}"
  echo "WEBHOOK_SECRET: ${WEBHOOK_SECRET:-NOT SET}"
  echo ""
  echo "Calling Python script..."

  export WEBHOOK_URL="${WEBHOOK_URL}"
  export WEBHOOK_SECRET="${WEBHOOK_SECRET}"

  /usr/bin/python3 /opt/mx-box/store_mail.py "$@" 2>&1

  EXIT_CODE=$?
  echo ""
  echo "Python exit code: $EXIT_CODE"
  echo "=== End ==="
} >> "$LOGFILE" 2>&1

exit $EXIT_CODE
