#!/bin/bash
# One-time setup of TinyIDS on the Pi. Everything stays inside ~/tinyids (undo: rm -rf ~/tinyids).
# You can also type these commands one by one (see the guide).
set -e
cd ~/tinyids
PROXY=http://172.31.2.3:8080          # college proxy (remove "--proxy $PROXY" and "-x $PROXY" on a hotspot)

echo "== 1. set the clock (the college blocks the time server)"
sudo date -s "$(curl -sI -x $PROXY https://www.google.com | grep -i '^date:' | cut -d' ' -f2-)"

echo "== 2. private Python for this project (virtual environment)"
python3 -m venv venv

echo "== 3. Python packages"
./venv/bin/pip install --proxy $PROXY numpy lightgbm scapy paho-mqtt onnxruntime psutil

echo "== 4. system libraries (installed only if missing)"
dpkg -s libgomp1 libpcap0.8 >/dev/null 2>&1 || sudo apt install -y libgomp1 libpcap0.8

echo "== 5. password for our broker (user tinyids)"
mosquitto_passwd -c -b broker/passwd tinyids tinyids123
chmod 0700 broker/passwd

echo "done. Start TinyIDS with: ./run_ids.sh"
