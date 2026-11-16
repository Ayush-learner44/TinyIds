#!/bin/bash
# Step 5 fix: record the BOT floods (all 10 sensors flood the Pi) as Flood rows. Run from retrain/testbed.
# The detector is stopped while recording (otherwise it would block the bots mid-recording).
# The recorder only runs WHILE the bots flood (they flood 25 s, we record 20 s of it), so every row is flood traffic.
export MSYS_NO_PATHCONV=1
P="docker compose -p retrain"

bots() {   # bots <udp|tcp> <file name>
    echo "== $2: bots $1 flood"
    $P exec -T sensor1 python -c "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); s.sendto(b'$1 25', ('172.28.60.255', 6667))"
    sleep 2
    $P exec -T recorder python record.py /data/$2.csv 20 interface eth0
    sleep 40                                   # bots back to normal, quiet before the next run
}

$P stop ids
bots tcp flood_bots_tcp_1
bots tcp flood_bots_tcp_2
bots tcp flood_bots_tcp_3
bots udp flood_bots_udp_1
$P start ids
echo "== done"
