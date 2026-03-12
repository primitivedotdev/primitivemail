#!/usr/bin/env bash
# Debug wrapper for store-mail.sh to troubleshoot delivery issues

echo "=== DEBUG ===" >> /tmp/delivery-debug.log
echo "Date: $(date)" >> /tmp/delivery-debug.log
echo "RECIPIENT env: $RECIPIENT" >> /tmp/delivery-debug.log
echo "USER var: $USER" >> /tmp/delivery-debug.log
echo "DOMAIN var: $DOMAIN" >> /tmp/delivery-debug.log
echo "All env:" >> /tmp/delivery-debug.log
env >> /tmp/delivery-debug.log
echo "==============" >> /tmp/delivery-debug.log

# Call the real script
exec /opt/mx-box/store-mail.sh
