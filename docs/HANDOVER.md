# TinyIDS handover (state on 13 Nov 2026, evening) — READ THIS FIRST in a new session

## Where things are
- Repo `C:\Users\HOME\Documents\iot\project`, branch **v4**, NOTHING committed yet (all changes only staged/unstaged). Do not push unless the user says so.
- Layout (restructured today): `pi/` = everything that runs on the Pi (and the Docker testbed uses the same code + models),
  `laptop/` = dashboard, attacks, NodeMCU firmware (`laptop/nodemcu_bot/`), bot master, Docker testbed (`laptop/testbed/`),
  `model/` = training (friend's area), `docs/` = notes/reports/results, `hardware_tests/` = old board/MQTT/CoAP tests.
- Lab results + all open problems: `docs/results/2026-11-13_pi_lab_v4/RESULTS.md` (read it fully).
- Local-only notes: `docs/MY_NOTES_model_and_next_steps.txt` (git-excluded), `docs/resume.txt` (gitignored).

## What changed in v4 (code)
- `pi/tinyids/address_watcher.py`: rule for ARP spoofing (same IP, new MAC) and IP-spoofed floods (one MAC, > 20 IPs in 5 s) -> block MAC (+ pin correct ARP entry). Router + own MAC trusted, router IP never blocked.
- `pi/tinyids/rules.py`: new `PortScanRule` (> 20 ports in 5 s = Recon, by rule; model "Flood" ignored while scanning). Tested on the Pi: works.
- `pi/tinyids/response.py`: `respond_mac`, `keep_admin_open` (admin laptop's SSH + open dashboard MQTT connection always accepted), rules appended with -A.
- `pi/run_tinyids.py`: wires the above; capture filter skips admin SSH + admin MQTT packets without SYN; `release_all` on Ctrl+C (finally).
- `pi/run_ids.sh`: SYN cookies line; passes extra args ("$@"), e.g. `./run_ids.sh --admin-ip 172.29.2.40 --models models_small`.
- `pi/models/` = 7 MB family model (old live one), `pi/models_small/` = < 1 MB (binary 974 KB, family 776 KB) from `model/make_small_models.py`.
  The small model worked LIVE on the Pi (SYN flood, bot TCP flood -> DDoS 3 senders, fewer false alarms, SHAP ~2.7 ms). Decision pending: make it the default after the bot UDP flood test.
- `pi/benchmark/compare_models.py` (7 MB vs 1 MB on the Pi), `model/make_ids_models.ipynb` (notebook of the training).
- `laptop/dashboard.py`: fixed KeyError 'reason' (history uses 'details').
- Attacks: `laptop/attacks/spoofed_flood.py`, `arp_spoof.py`; Docker: `spoofed_flood syn|udp`, `arp_spoof`.
- `laptop/nodemcu_bot/nodemcu_bot.ino`: GATEWAY_IP = 172.29.2.43 (Pi IP on 13 Nov; re-flash if the Pi IP changes). NODE_NAME per board.
- `.gitattributes`: shell scripts keep LF.

## Lab setup that worked (13 Nov)
Pi 172.29.2.43 (user pi), laptop 172.29.2.40, node1 .42, node2 .60, node3 .41, college Wi-Fi IIITA, proxy 172.31.2.3:8080.
Copy code: `scp` files from `pi\` to `pi@<PI>:~/tinyids/` (files of the package go to `~/tinyids/tinyids/`).
Pi: `cd ~/tinyids && ./run_ids.sh --admin-ip <LAPTOP_IP> [--models models_small]`. Laptop: `streamlit run laptop/dashboard.py -- <PI_IP>`.
Attacks from an ADMIN PowerShell in `laptop\attacks`. Bots: `python laptop\bot_master.py <PI_IP> tcp_flood --seconds 5`.
iptables had to be installed on the Pi (`sudo apt -o Acquire::http::Proxy=http://172.31.2.3:8080 install -y iptables`) -> add to setup_pi.sh.

## Open work, in order (user wants to do these at home, Docker testbed first)
1. UDP flood took the Pi off the network (285 pps, port 5683). Reproduce in Docker, try lower rates / ICMP rate limit / iptables UDP limit; next Pi test on phone hotspot or Ethernet. Bot UDP flood with the small model also untested live.
2. RAM: TinyIDS = ~128 MB RSS on the Pi (target < 100 MB). Find what uses it in the Docker ids container (import by import), cut (e.g. scapy.all -> specific layers), then re-measure on the Pi (`ps -eo rss,args | grep run_tinyids`).
3. RQ2 benchmark `pi/benchmark/rq2_benchmark.py` has NEVER run on the Pi (Gemini's "60-85 MB / PASSED" numbers are not measured). Run on next lab visit (~2 min). Sizes from the laptop are fine.
4. Laptop attacks only ~300 pps (scapy one packet at a time) -> batch sending.
5. False alarms on NodeMCUs at boot/reconnect (low confidence 0.3-0.7) and "Recon" labels on bots after TCP floods -> record own traffic, add to training (friend), retrain small model.
6. setup_pi.sh: install iptables; NodeMCU without hard-coded Pi IP (optional).
7. Optional: ARP spoof / spoofed flood on the real Pi (hotspot), energy (needs USB meter).
8. Commit v4 when the user says; update START.md "known issues" from RESULTS.md.

## How the user wants to work
- Explain simply; keep code simple (small classes, simple names) — the prof may ask to explain it.
- In the lab: ONE step at a time, every command in its own box, say "one command"; wait for output.
- Record every result and fix in RESULTS.md as it happens.
- Be honest about what is measured vs projected; don't trust old Gemini numbers without checking.
- Never push / commit without being asked; private files stay out of git.
