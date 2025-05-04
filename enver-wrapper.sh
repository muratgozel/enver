#!/bin/bash

echo "Original command: $SSH_ORIGINAL_COMMAND" >> /tmp/ssh_debug.log

/usr/local/bin/enver --developer-id "$1" $SSH_ORIGINAL_COMMAND
