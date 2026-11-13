#!/bin/bash
# Start our broker (port 1884) in the background, then the TinyIDS detector. Ctrl+C stops both.
cd ~/tinyids
sudo sysctl -q -w net.ipv4.tcp_syncookies=1     # SYN cookies: the kernel survives SYN floods (extra protection)
mosquitto -c /home/pi/tinyids/broker/tinyids_broker.conf -d
echo "our broker is running on port 1884"
trap 'pkill -f tinyids_broker.conf; echo "our broker stopped"' EXIT
sudo ./venv/bin/python run_tinyids.py --interface wlan0 --port 1884 "$@"     # e.g. ./run_ids.sh --admin-ip 172.29.2.40
