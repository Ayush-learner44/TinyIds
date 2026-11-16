#!/bin/bash
# Re-test only the bot TCP flood after "skip senders that are already blocked" (run from retrain/testbed).
export MSYS_NO_PATHCONV=1
P="docker compose -p retrain"
mark() { echo "== $(date +%H:%M:%S) $*"; }
sleep 20
mark "bots tcp flood: all 10 sensors (DDoS)"
$P exec -T sensor1 python -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.sendto(b'tcp 15', ('172.28.60.255', 6667))"
sleep 75
mark "normal traffic, 3 min (quarantine ends after 120 s)"; sleep 180
mark "done"
