#!/bin/bash
echo "PIPE WORKS: $(date) - Recipient: $1" >> /tmp/pipe-test.log
cat > /dev/null
exit 0
