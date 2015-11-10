#!/bin/bash
ssh-keygen -t rsa -N '' -f /opt/securehoney/keys/honeykey
make
make install
cp sshpot /opt/securehoney/sshpot
chmod +x /opt/securehoney/sshpot
