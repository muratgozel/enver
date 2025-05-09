#!/usr/bin/env bash

apt update
apt install -y openssh-server redis-server python3 python3-pip python3-venv

mkdir -p /usr/local/lib/enver
mkdir -p /var/log/enver

groupadd -f enver
useradd -g enver -d /home/enver -m -s /bin/bash enver
chmod -R 770 /var/log/enver
chown enver:enver /var/log/enver
chown enver:enver /usr/local/lib/enver

cat > /etc/ssh/sshd_config.d/enver.conf << EOF
# Enver SSH Configuration
Match Group enver
    AllowTcpForwarding no
    X11Forwarding no
    AllowAgentForwarding no
    PermitTTY no
EOF

cp enver.sh /usr/local/bin/enver
chmod +x /usr/local/bin/enver
cp enver-ssh-wrapper.sh /usr/local/bin/enver-ssh-wrapper
chmod +x /usr/local/bin/enver-ssh-wrapper

cp -a . /usr/local/lib/enver/
cd /usr/local/lib/enver/ || exit

if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
else
    echo "Virtual environment already exists."
fi
source .venv/bin/activate
pip install -r requirements.txt
deactivate

sudo -u enver bash -c '/usr/local/bin/enver/enver init'

systemctl restart ssh
