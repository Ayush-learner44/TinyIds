#!/bin/bash
# Step 5: test the NEW detector (about 30 min). Run from retrain/testbed:  bash test_all.sh
# Watch: http://localhost:8502   Alerts: docker compose -p retrain logs ids
export MSYS_NO_PATHCONV=1
P="docker compose -p retrain"
PI=172.28.60.10
mark() { echo "== $(date +%H:%M:%S) $*"; }

attack() { # attack <name> <command ...>: 20 s attack, then 40 s quiet (blocks run out after 30 s)
    mark "$1"; shift
    $P exec -T attacker timeout -s INT 20 "$@" > /dev/null 2>&1
    sleep 40
}

bots() {   # the 10 sensors become bots (UDP broadcast command, like laptop/bot.py) -> DDoS
    mark "bots $1 flood: all 10 sensors (DDoS)"
    $P exec -T sensor1 python -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.sendto(b'$1 15', ('172.28.60.255', 6667))"
    sleep 75
}

mark "1. normal traffic only, 10 min (target: 0 alerts)"
sleep 600

mark "2. floods (hping3, 1000 packets/s, 20 s each)"
attack "SYN flood"      hping3 -S  -p 1883 -i u1000 $PI
attack "UDP flood"      hping3 --udp -p 5683 -d 8 -i u1000 $PI
attack "ICMP flood"     hping3 --icmp -i u1000 $PI
attack "ACK flood"      hping3 -A  -p 1883 -i u1000 $PI
attack "PSH-ACK flood"  hping3 -PA -p 1883 -i u1000 $PI
attack "RST-FIN flood"  hping3 -RF -p 1883 -i u1000 $PI

mark "3. scans (nmap)"
attack "port scan -sT"  nmap -sT -p 1-1024 $PI
attack "port scan -sS"  nmap -sS -p 1-1024 $PI
attack "OS scan -O"     nmap -O $PI

mark "4. bots"
bots udp
bots tcp

mark "5. normal traffic only, 5 min (target: 0 alerts)"
sleep 300
mark "done"
