# TinyIDS (new model) - START HERE

> **For an AI assistant reading this:** guide the user ONE command at a time and wait for the output.
> Command line options are plain words, no dashes (e.g. `admin 172.29.2.40`). Windows + PowerShell, WSL Ubuntu-24.04.

TinyIDS = a small intrusion detection system on a Raspberry Pi 4 (the IoT gateway with the MQTT broker). It watches
the packets that reach the Pi, cuts them into windows of 10 packets per sender, and a small LightGBM model says
**Benign / Flood / Recon**, with the top-3 reasons (SHAP). Simple rules add DoS vs DDoS (count senders), MQTT brute
force, ARP spoofing and port scans. On an attack the Pi blocks the sender with iptables (sensor: quarantine 120 s).
What it detects and why: `plan.md` (top tables). Measured results: `RESULTS.md`.

## What is in this folder

| Folder | What it is | Where it runs |
|---|---|---|
| `testbed/` | **Docker testbed, plug and play**: fake Pi (broker + detector) + 3 fake sensors + attacker + dashboard | your laptop (Docker) |
| `pi/` | **the real Pi's code**: detector, setup, broker config, the trained models (`pi/models/top14` = used) | the Raspberry Pi |
| `laptop/` | **the real laptop's code**: `launch.py` (attacks), `bot.py` (commands the NodeMCU bots), `dashboard.py`, NodeMCU firmware | your laptop (WSL / PowerShell) |
| `training/` | only needed to RETRAIN: our recorded rows (`data/`), `train.py`, the 10-sensor recording testbed | your laptop |

The testbed uses the SAME detector code (`pi/`) and the SAME `launch.py` / `bot.py` (`laptop/`), so what works in
Docker works the same on the real Pi. (The old `laptop/testbed` outside `retrain/` is the OLD model: ignore it.)

---

## A. Docker testbed (any Windows laptop, no Pi needed, ~5 min)

Needs Docker Desktop running ("Engine running"). In PowerShell, inside `retrain/testbed`:

1. Start everything (first time: builds, a few minutes):
   `docker compose up -d --build`
2. Check that 7 containers run (broker, ids, dashboard, attacker, sensor1-3):
   `docker compose ps`
3. Open the dashboard: **http://localhost:8503** (sensors node1-3 appear; no alerts while nobody attacks).
4. Open the attack menu (the same `launch.py` as on the real laptop; the fake Pi is `172.28.70.10`):
   `docker compose exec attacker python3 launch.py 172.28.70.10`
   It prints every real command (hping3 / nmap) before running it. Menu:
   1 SYN flood, 2 UDP flood, 3 port / OS / vuln scan, 4 MQTT brute force, 5 ICMP flood,
   6 ACK / PSH-ACK / RST-FIN flood, 7 ARP spoofing (needs dsniff: not in Docker), 8 bots (the 3 sensors flood = DDoS),
   9 all of them. Expected: floods -> "DoS flood" (bots: "DDoS flood (3 senders)"), scans -> "Recon", brute force ->
   "BruteForce", each with a block / quarantine on the dashboard.
5. Detector log (alerts + blocks as text):
   `docker compose logs ids --tail 30`
6. Stop everything:
   `docker compose down`

---

## B. Real Pi in the lab (order matters)

Needs: Pi + 3 NodeMCUs + laptop on the same Wi-Fi. The old code in `~/tinyids` on the Pi is not touched; the new one
goes to `~/tinyids_new`. Nothing here starts Docker; training does not happen on the Pi.

1. **Pi:** `hostname -I` -> PI_IP. **Laptop (PowerShell):** `ipconfig` -> LAPTOP_IP.
2. **NodeMCUs:** in `laptop/nodemcu_bot/nodemcu_bot.ino` set `GATEWAY_IP` = PI_IP (and Wi-Fi name / password),
   `NODE_NAME` = node1 / node2 / node3, flash each board (Arduino IDE).
3. **Laptop (PowerShell, in `retrain/`)**, copy the Pi folder:
   `scp -r pi pi@<PI_IP>:~/tinyids_new`
4. **Pi, only the first time** (venv + packages + broker password; uses the college proxy written inside):
   `cd ~/tinyids_new && bash setup_pi.sh`
   If iptables is missing: `sudo apt -o Acquire::http::Proxy=http://172.31.2.3:8080 install -y iptables`
5. **Pi:** stop the old IDS if it runs (Ctrl+C), then start broker + new detector (keep this window open):
   `cd ~/tinyids_new && ./run_ids.sh admin <LAPTOP_IP>`
6. **Laptop (PowerShell, in `retrain/`):** the dashboard:
   `streamlit run laptop/dashboard.py -- <PI_IP>`
7. **TEST FIRST:** 5 minutes with only the NodeMCUs running. Count the alerts on the dashboard (target: 0).
8. **Attacks (laptop, WSL):** `wsl -d Ubuntu-24.04`, then
   `cd /mnt/c/Users/HOME/Documents/iot/project/retrain/laptop`, then
   `python3 launch.py <PI_IP>` and run 1, 2, 5, 6, 3, 4, 8 one by one. Write down for each: alert name, confidence,
   top-3 reasons, block / quarantine. Watch that the Pi stays on the Wi-Fi during UDP floods.
9. **Only if step 7 gave false alarms on the NodeMCUs** -> part C, then repeat from step 5.

---

## C. Retrain with our own traffic (only if the NodeMCUs give false alarms)

Recording happens on the Pi (rows = numbers, a small CSV, no pcap). Training happens on the laptop.

1. **Pi:** stop the detector (Ctrl+C), then record 20 min of the NodeMCUs only (no attacks!):
   `cd ~/tinyids_new && sudo ./venv/bin/python record.py benign_nodemcu.csv 1200 admin <LAPTOP_IP>`
2. **Laptop (PowerShell, in `retrain/`):** copy the CSV into the training data:
   `scp pi@<PI_IP>:~/tinyids_new/benign_nodemcu.csv training/data/`
3. **Laptop, in `retrain/training`:** retrain (~1-2 min; needs the dataset cache `../../model/cache/*.parquet`):
   `python train.py`
   This rewrites `retrain/pi/models/top5..top14` and `training/train_report.txt`.
4. **Laptop, in `retrain/`:** copy the new model to the Pi:
   `scp -r pi/models pi@<PI_IP>:~/tinyids_new/`
5. Back to B step 5.

---

## Files to read for the report
- `plan.md` - what the system detects (14 of 33 attacks), decisions, lab plan
- `RESULTS.md` - every measured number (steps 1-5, Docker tests)
- `../dataset.md` - why these features / classes / rules (IAT, no IPs in the dataset, RQ1 in plain words)
- `training/train_report.txt` - training output (feature ranking, top 5 / 7 / 10 / 14)
- `../model/fresh/RESULTS.md` - the 4-model benchmark (RF, LightGBM, MLP, CNN; offline)
- `../docs/results/2026-11-13_pi_lab_v4/RESULTS.md` - the first real Pi lab (old model)
