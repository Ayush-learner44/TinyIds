#!/bin/bash
# Step 5 re-test after adding the bot flood rows: scans (still Recon?), bot floods (now Flood?), quiet (0 alerts?).
export MSYS_NO_PATHCONV=1
P="docker compose -p retrain"
PI=172.28.60.10
mark() { echo "== $(date +%H:%M:%S) $*"; }
scan() { mark "$1"; shift; $P exec -T attacker timeout -s INT 20 "$@" > /dev/null 2>&1; sleep 40; }
bots() {
    mark "bots $1 flood: all 10 sensors (DDoS)"
    $P exec -T sensor1 python -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.sendto(b'$1 15', ('172.28.60.255', 6667))"
    sleep 75
}

$P restart ids > /dev/null 2>&1               # load the new model
sleep 15
mark "1. normal traffic, 3 min"; sleep 180
scan "port scan -sT" nmap -sT -p 1-1024 $PI
scan "port scan -sS" nmap -sS -p 1-1024 $PI
scan "OS scan -O"    nmap -O $PI
bots tcp
bots udp
mark "2. normal traffic, 3 min"; sleep 180
mark "done"
