# First end-to-end run on real hardware — 07 Nov 2026, 12:19–12:46 (college Wi-Fi, IIITA lab)

## Setup
| Device | IP | Role |
|---|---|---|
| Raspberry Pi 4 (lab Pi, Debian trixie, Python 3.13) | 172.29.1.135 | our Mosquitto on port 1884 + TinyIDS detector (`run_tinyids.py`, interface wlan0) |
| NodeMCU "node1" (`nodemcu_bot.ino`) | 172.29.2.58 or .49 | sensor, every 2 s |
| NodeMCU "node2" | 172.29.2.49 or .58 | sensor, every 2 s |
| Windows laptop | 172.29.2.47 | SSH to the Pi, dashboard (`streamlit run dashboard.py -- 172.29.1.135`), attacker |

Models: `deploy/pi/models` (now `pi/models`) = binary LightGBM (1,014 KB) + 7-class family LightGBM (7,032 KB), 30 live features, no IAT.

## What worked (pipeline end to end)
- Setup on the Pi: venv + numpy, lightgbm 4.7.0, scapy 2.8.0, paho-mqtt 2.2.0, onnxruntime 1.31.1, psutil (through the college proxy). `all OK`.
- Our broker listened on 0.0.0.0:1884; both NodeMCUs connected; readings shown on the laptop dashboard (Sensors table node1, node2).
- Detector captured live traffic on wlan0, classified windows, explained alerts with SHAP and published them over MQTT; dashboard showed everything live.
- **SYN flood from the laptop (12:44:36–12:44:47)**: `python syn_flood.py 172.29.1.135 --seconds 10` sent 3,173 packets in 10 s (317 packets/s; Python on Windows is slower than the 1,000 requested).
  - Dashboard traffic graph: spike to ~300–400 packets/s.
  - Alerts: **Flood from 172.29.2.47 (laptop), confidence 1.00, every second 12:44:38–12:44:47**, top SHAP reasons `ack_flag_number, psh_flag_number, syn_flag_number` / `Rate, AVG, syn_flag_number`.

## Measured on the Pi (from the dashboard)
- Model time per window: **~2–4 ms** (binary + family LightGBM).
- SHAP (TreeSHAP) time per alert: **~46–96 ms** (proposal target < 50 ms: borderline).

## Problems seen
1. **Both boards first ran with NODE_NAME "node1"** → same MQTT client ID `bot-node1` → the broker kicked one out every time the other logged in → endless reconnects (Serial Monitor: `MQTT ... OK` / `online` repeating). The reconnect bursts were classified as **Flood** (confidence 0.95–1.00, reasons `AVG, Tot size, psh/syn_flag_number`) from 172.29.2.58 and .49, 12:35–12:41. **Fixed** by setting `NODE_NAME "node2"` on the second board.
2. **False alarms on normal traffic** (known issue):
   - NodeMCU sensor traffic → "Spoofing" (conf 0.3–0.8, reasons `Tot size, flow_duration, Header_Length`), sometimes "BruteForce" (`Std, Header_Length, flow_duration`) or "Recon".
   - Laptop's own SSH session to the Pi → "BruteForce" every few seconds (conf 0.5–0.98, reasons `SSH, flow_duration, Header_Length`) and occasional "Flood" (`flow_duration, psh_flag_number, ack_flag_number`).
   - Cause: the dataset's benign traffic (cameras, web) looks different from our MQTT sensors and SSH. Fix later: record normal testbed traffic and add it to training as Benign (calibration), and/or require several windows in a row before alerting.
3. SHAP time per alert sometimes above 50 ms.
4. Clean-up: the last command was typed as `pkill -f tinyids_broker.confnf` — check next time with `pgrep -af tinyids_broker` and stop it with `pkill -f tinyids_broker.conf` if still running.

## Not done yet (next lab visit)
UDP flood, port scan, MQTT brute force, NodeMCU bot (`bot_master.py`), RQ2 benchmark on the Pi (`benchmark/rq2_benchmark.py`), energy (needs USB power meter).

## Files
- `dashboard_normal_traffic.png` — dashboard before the attack (false alarms, model 2.29 ms, SHAP 50.55 ms)
- `dashboard_syn_flood_detected.png` — traffic spike and Flood alert from the laptop
- `nodemcu_two_boards_same_name.png` — Serial Monitor showing the reconnect loop
