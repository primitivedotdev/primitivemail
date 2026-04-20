#!/bin/bash
# Debug script to see what Postfix passes to mailbox_command
env > /tmp/delivery-env.log
cat > /tmp/delivery-stdin.log
