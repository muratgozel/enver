#!/usr/bin/env bash

if [ ! -d "/usr/local/bin" ]; then
    echo "No directory found as /usr/local/bin"
    exit 1
fi

sudo cp enver-client.sh /usr/local/bin/enver
sudo chmod +x /usr/local/bin/enver
