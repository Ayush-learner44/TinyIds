#!/bin/bash
# Step 3: record our own rows (about 50 minutes). Run from retrain/testbed:  bash record_all.sh
# Every file = one CSV in retrain/data/. Labels are given later by the training script:
#   rows from the attacker (172.28.60.66) = the attack of that file, rows from the sensors = Benign.
export MSYS_NO_PATHCONV=1                       # Git Bash on Windows: don't rewrite /data paths
P="docker compose -p retrain"
PI=172.28.60.10                                 # the "Pi" (broker)

rec() {    # rec <file name> <seconds>
    $P exec -T recorder python record.py /data/$1.csv $2 interface eth0
}

attack() { # attack <file name> <command ...>: record 45 s, the attack runs 30 s inside it
    name=$1; shift
    echo "== $name: $*"
    rec "$name" 45 &
    sleep 5
    $P exec -T attacker timeout -s INT 30 "$@" > /dev/null 2>&1
    wait
}

echo "== 1. benign: 10 sensors, 30 min (sensors restarted twice, so their start-up bursts are recorded too)"
rec benign 1800 &
sleep 600; $P restart sensor1 sensor2 sensor3 sensor4 sensor5
sleep 600; $P restart sensor6 sensor7 sensor8 sensor9 sensor10
wait

echo "== 2. floods (hping3, 1000 packets/s, 30 s each)"
attack flood_syn      hping3 -S  -p 1883 -i u1000 $PI
attack flood_udp      hping3 --udp -p 5683 -d 8 -i u1000 $PI
attack flood_icmp     hping3 --icmp -i u1000 $PI
attack flood_ack      hping3 -A  -p 1883 -i u1000 $PI
attack flood_pshack   hping3 -PA -p 1883 -i u1000 $PI
attack flood_rstfin   hping3 -RF -p 1883 -i u1000 $PI
attack flood_syn_slow hping3 -S  -p 1883 -i u10000 $PI       # 100 packets/s: floods are not always fast

echo "== 3. recon (nmap)"
attack recon_connect  nmap -sT -p 1-1024 $PI
attack recon_syn      nmap -sS -p 1-1024 $PI
attack recon_os       nmap -O $PI
attack recon_version  nmap -sV --top-ports 100 $PI
attack recon_ping     nmap -sn -PE 172.28.60.0/24
attack recon_vuln     nmap --script vuln -p 1883 $PI

echo "== done. Rows per file:"
for f in ../data/*.csv; do echo "$(($(wc -l < "$f") - 1))  $f"; done
