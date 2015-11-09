#!/bin/bash
ssh-keygen -t rsa -N '' -f /opt/SecureHoney/keys/honeykey
make
make install
cp sshpot /opt/SecureHoney/sshpot
chmod +x /opt/SecureHoney/sshpot
