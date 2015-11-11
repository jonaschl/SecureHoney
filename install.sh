#!/bin/bash
mkdir -p /opt/securehoney/keys
mkdir -p /opt/securehoney/logs
ssh-keygen -t rsa -N '' -f /opt/securehoney/keys/honeykey
make
cp sshpot /opt/securehoney/sshpot
chmod +x /opt/securehoney/sshpot
