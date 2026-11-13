# TinyIDS

Lightweight, explainable intrusion detection for an IoT gateway (Raspberry Pi 4), CICIoT2023 dataset.

## Folders: which one do I use?

| Folder | What it is | Where it runs |
|---|---|---|
| **`pi/`** | **The detector.** Copy this whole folder to the Pi as `~/tinyids`. The Docker testbed uses the SAME code and models. | Raspberry Pi (and Docker) |
| **`laptop/`** | Dashboard, attack scripts, NodeMCU bot firmware, bot master, and the Docker testbed (`laptop/testbed/`) | your laptop |
| `model/` | Training the models (offline ML work) | laptop |
| `docs/` | Proposal, reports, PDFs, guides, results, notes | - |
| `hardware_tests/` | Early tests: ESP8266 board, MQTT, CoAP, first Pi gateway test, drivers | - |

## pi/ in detail
| File | What it does |
|---|---|
| `run_tinyids.py` | starts the detector (`./run_ids.sh` starts broker + detector) |
| `tinyids/` | detector code: features, windows, detector (models + SHAP), alert filter, rules, address watcher, response (iptables), publisher, settings |
| `models/` | the live models: `binary.txt`, `family.txt`, `meta.json` |
| `models_small/` | < 1 MB versions (not used yet: weaker on our live bot traffic, see `models_small/report.txt`) |
| `broker/` | our Mosquitto config (port 1884) |
| `setup_pi.sh` | one-time setup on the Pi |
| `benchmark/` | RQ2 speed benchmark of all compressed models on the Pi |

## Quick start
```
# Docker testbed (laptop)
cd laptop/testbed
docker compose up -d --build            # dashboard: http://localhost:8501
docker compose exec attacker syn_flood  # also: udp_flood, port_scan, mqtt_bruteforce, spoofed_flood syn|udp,
                                        #       arp_spoof, bot_master udp_flood 10
# Pi
cd ~/tinyids && ./run_ids.sh
# Laptop, against the Pi (PowerShell as Administrator)
streamlit run laptop/dashboard.py -- <PI_IP>
python laptop/attacks/syn_flood.py <PI_IP>
```
More detail for the ML work: `START.md`.
