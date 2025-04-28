#!/usr/bin/env bash

apt update
apt install -y openssh-server redis-server python3 python3-pip python3-venv

mkdir -p /usr/local/lib/enver
mkdir -p /var/log/enver
mkdir -p /etc/enver

groupadd -f enver

cat > /etc/ssh/sshd_config.d/enver.conf << EOF
# Enver SSH Configuration
Match Group enver
    AllowTcpForwarding no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
    ForceCommand /usr/local/bin/enver
EOF

cp enver /usr/local/bin/enver
chmod +x /usr/local/bin/enver

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
else
    echo "Virtual environment already exists."
fi
source .venv/bin/activate
pip install -r requirements.txt

./enver init

systemctl restart ssh
