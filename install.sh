#!/bin/bash
mkdir -p /opt/securehoney/keys
mkdir -p /opt/securehoney/logs
if [ -f /opt/securehoney/keys/honeykey ]; then
  echo -e "\033[32mKey found\033[0m"
else
  echo -e "\033[31mNo Key foudn, we will generate a key\033[0m"
  ssh-keygen -t rsa -N '' -f /opt/securehoney/keys/honeykey
fi
echo -e "\033[32mCompile sshpot\033[0m"
make
make clean
cp sshpot /opt/securehoney/sshpot
chmod +x /opt/securehoney/sshpot
