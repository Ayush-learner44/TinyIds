# Plan: a new small LightGBM model trained with our own traffic (written 16 Nov 2026)

> **HOW TO RUN anything (Docker testbed, real Pi, retraining): `START.md`.** Folders were reorganized on 16 Nov evening:
> `testbed/` = the plug-and-play Docker testbed (3 sensors), `training/` = `train.py` + `data/` + the 10-sensor
> recording testbed (`training/record_testbed/`). Paths below that say `retrain/testbed/...`, `retrain/data/`,
> `retrain/train.py` or `retrain/laptop/testbed` now live there.

> ## ⭐ WHAT THE FINISHED SYSTEM CAN TELL APART (if everything works)
>
> The model gives 3 answers (Benign / Flood / Recon); the rules add the rest.
>
> | Alert | Who decides | What the Pi does |
> |---|---|---|
> | **DoS flood** (1 sender) | model says Flood + rule counts 1 sender | block 30 s (a sensor: quarantine 120 s) |
> | **DDoS flood** (**2+ senders**) | model says Flood + rule counts the senders | block / quarantine each sender |
> | **Recon** (any scan) | model | block |
> | **Recon, port scan** | port-scan rule | block |
> | **Brute force** (MQTT logins) | rule | block |
> | **ARP spoofing** | rule | block the MAC + fix the Pi's ARP table |
> | **IP-spoofed flood** | rule | block the MAC |
> | **Benign** | model | nothing |
>
> = 7 kinds of attack alerts + normal traffic. An unsure alert is rate-limited instead of blocked.
> DDoS threshold: **2 senders** (in the `retrain/` copy: `ddos_sources = 2`; the original `pi/` still says 3).

> ## ⭐ WHICH OF THE 33 DATASET ATTACKS WE CATCH (if everything works): 14 of 33 (15 of 34 classes with Benign)
>
> | Dataset attack | Count | Caught by | Shown as | Mitigation |
> |---|---|---|---|---|
> | DDoS: SYN, UDP, ICMP, TCP, PSH-ACK, RST-FIN flood | 6 | model (Flood) + sender-count rule | "DDoS flood" | block / quarantine |
> | DoS: SYN, UDP, TCP flood | 3 | model (Flood) + sender-count rule | "DoS flood" | block / quarantine |
> | Recon: port scan, OS scan, vulnerability scan | 3 | model (Recon); port scan also the rule | "Recon" | block |
> | Dictionary brute force | 1 | rule (MQTT logins) | "BruteForce" | block |
> | ARP spoofing | 1 | rule | "ARP spoofing" | block the MAC + fix the ARP table |
> | **Total** | **14** | | | |
>
> **Maybe (untested):** the 3 fragmentation floods (ACK, UDP, ICMP: floods, but not in training) and the SynonymousIP
> flood (fake source IPs: the IP-spoofing rule might catch it) -> best case **18 of 33**.
> **Dropped on purpose (16 Nov):** ping sweep and host discovery: they send < 10 packets to the Pi, so no window ever
> fills (0 rows recorded). Not detected, not mitigated, not claimed.
> **Not covered:** Web (6: SQL injection, command injection, XSS, backdoor, uploading, browser hijacking),
> Mirai (3), HTTP flood (2) + SlowLoris (need a web server), DNS spoofing, + the 2 dropped scans = 15.
> **Honest note:** the model DETECTS these but doesn't NAME each one ("Flood", not "SYN flood"). The exact name comes
> from the rules (DoS / DDoS, port scan) or the SHAP reasons (`syn_flag_number` on top = SYN flood).

**Rule for this folder:** everything new happens inside `retrain/`. Nothing in `pi/`, `laptop/`, `docs/`, `model/`
or `dataset/` is changed. If code or a testbed is needed, only the essential files are COPIED into `retrain/` and changed
here. The dataset is only READ.

Background and reasons: `dataset.md` (project root).

---

## Step 0: decide the classes (the user decides)
Suggestion:
- **Keep:** Benign (dataset + ours), Flood (SYN, UDP, ICMP, TCP, PSH-ACK, RST-FIN floods, DoS + DDoS),
  Recon (port scan, OS scan, vulnerability scan; ping sweep + host discovery dropped 16 Nov).
- **Drop from training:** Web, Mirai, HTTP flood, SlowLoris, SynonymousIP, fragmentation floods, Brute force,
  Spoofing (rules handle brute force and spoofing; their dataset rows look like normal traffic).
- Open choices: name the flood type or just "Flood"; one 3-class model or two models (binary + family).

## Step 1: check 2 things on the dataset (reading data only, no training)
- The `Number` column = packets per row -> did floods really use 100-packet rows or 10? Decides the windows.
- The real meaning of `Rate` (UDP flood ~8,000 vs SYN flood ~5 looks odd) -> can pps be used as a feature?

## Step 2: code changes (in COPIES inside `retrain/`)
- `features.py`: `Protocol Type` = most common protocol in the window (as the dataset); `Rate` = packets per second
  of the window (only if step 1 says ok).
- A **record** option: `run_tinyids.py record benign.csv` writes feature rows to a CSV instead of classifying.
  No pcaps are saved (no GBs).
- Windows: keep 10 / 100 packets, or "every 2 seconds per sender", depending on step 1.

## Step 3: record our own rows
- Docker (a copied testbed inside `retrain/`): 10 fake sensors, ~30 min -> benign rows.
- Docker: hping3 SYN / UDP / ICMP floods + nmap scans, a few minutes each -> our attack rows (small amount, only so
  the model can't use "our-style numbers = benign").
- Lab: the real NodeMCUs, 15-20 min, no attacks running (see `nextlab.md`).

## Step 4: train LightGBM only (RF / MLP / CNN stay as they are for RQ2)
- Start from the ~14 matching features: `Protocol Type, Tot size, Min, Max, AVG, Std, syn_flag_number,
  ack_flag_number, psh_flag_number, rst_flag_number, fin_flag_number, TCP, UDP, ICMP` (+ pps if step 1 allows).
- Data: dataset rows of the kept classes (20% sample, like now) + our rows; split train / validation / test.
- **Mini RQ1:** rank the features (LightGBM `feature_importance("gain")` + mean |SHAP|), retrain with the top
  5 / 7 / 10 / 14, show the scores. **The user picks the final number.**
- The training script lives in `retrain/` (a copy of `model/make_small_models.py`, changed).

## Step 5: test
1. **Offline:** scores on the dataset's test rows (binary F1, per-class), and on our own held-out rows: how many
   NodeMCU / sensor rows get flagged (target ~0).
2. **Docker (copied testbed):** 10 sensors, 10 min, no attacks -> count false alarms (target 0); then every attack ->
   caught and named right?
3. **Lab:** the same on the real Pi + timing and RAM.

## Step 6: write down the results
Results go into `retrain/RESULTS.md`. Only after the user says ok: move the new model / code into `pi/` and update
README / HANDOVER / `dataset.md`.

---

## Decisions (filled in by the user)
- Classes: **Benign / Flood / Recon** (16 Nov)
- Models: **one 3-class LightGBM model** (16 Nov)
- DDoS = **2+ senders** flooding at the same time (copy of `settings.py`: `ddos_sources = 2`) (16 Nov)
- Windows: **one 10-packet window per sender, timeout 30 s** (no 100-packet window, no window-size check) (16 Nov)
- Features: **no `Rate` / pps** (step 1: unusable). Start from 14: `Protocol Type, Tot size, Min, Max, AVG, Std,
  syn_flag_number, ack_flag_number, psh_flag_number, rst_flag_number, fin_flag_number, TCP, UDP, ICMP` (16 Nov)

---

## STATUS 16 Nov: steps 0-5 done in Docker (results: `RESULTS.md`). Use model **`pi/models/top14`** (the default now).

## Folders (all complete, copied from the old ones and changed)
- `retrain/pi/` = everything for the Pi -> copy to **`~/tinyids_new/`** on the Pi (the old `~/tinyids` stays):
  `run_tinyids.py`, `tinyids/`, `record.py`, `run_ids.sh`, `setup_pi.sh`, `broker/`, `models/top5..top14`.
- `retrain/laptop/` = `launch.py` (new: 5 ICMP flood, 6 ACK / PSH-ACK / RST-FIN flood, 3 port / OS / vuln scan),
  `bot.py`, `dashboard.py`, `nodemcu_bot/nodemcu_bot.ino` (temperature only, no humidity),
  `testbed/` (Docker: new detector + 3 temp-only sensors + attacker + dashboard on http://localhost:8503).
- `retrain/testbed/` = the recording testbed (10 sensors, recorder) used for steps 3-5.
- `retrain/train.py` = training; `retrain/data/` = our recorded rows.

**WARNING (not tested):** removing humidity makes the sensor's MQTT packet ~20 bytes smaller. The model learned the
sensors WITH humidity. If the temp-only sensors / NodeMCUs give false alarms: record them (`record.py`) and retrain
(`python train.py`, ~1 min). Do this in the lab with the real NodeMCUs anyway.

## Lab order (one command at a time)
1. Pi: `hostname -I` -> PI_IP. Laptop: `ipconfig` -> LAPTOP_IP.
2. Flash `retrain/laptop/nodemcu_bot/nodemcu_bot.ino` on the 3 NodeMCUs (GATEWAY_IP = PI_IP, NODE_NAME node1/2/3).
3. Copy: `scp -r retrain\pi pi@<PI_IP>:~/tinyids_new`
4. Pi, once: `cd ~/tinyids_new && bash setup_pi.sh` (venv, packages, broker password).
   Also once if missing: `sudo apt install -y iptables` (with the college proxy).
5. Pi: stop the old IDS if running (Ctrl+C), then `cd ~/tinyids_new && ./run_ids.sh admin <LAPTOP_IP>`
6. Laptop (PowerShell): `streamlit run retrain\laptop\dashboard.py -- <PI_IP>`
7. 5 min normal traffic (NodeMCUs only): count false alarms. If there are any: Ctrl+C the IDS, then
   `sudo ./venv/bin/python record.py benign_nodemcu.csv 1200 admin <LAPTOP_IP>` (20 min), copy the CSV to
   `retrain/data/` on the laptop, `python train.py`, copy `pi/models/top14` to the Pi again, restart (step 5).
8. Attacks from WSL (`wsl -d Ubuntu-24.04`, `cd .../retrain/laptop`, `python3 launch.py <PI_IP>`):
   1 SYN, 2 UDP, 5 ICMP, 6 ACK / PSH-ACK / RST-FIN, 3 port + OS scan, 4 brute force, 8 bots udp + tcp.
   For each: alert name, confidence, top-3 reasons, action. Watch that the Pi stays on the Wi-Fi during UDP floods.
9. `./venv/bin/python ../tinyids/benchmark/rq2_benchmark.py` (RQ2, never run on the Pi), RAM:
   `ps -eo rss,args | grep run_tinyids`. Record the demo video.
10. Write everything into `RESULTS.md` (a new "Lab" section).

## For the report (files another AI / teammate should read)
- `retrain/plan.md` (this file: what the system detects, 14 of 33 table), `retrain/RESULTS.md` (all measured numbers)
- `dataset.md` (root: why these features / classes, IAT, rules, RQ1 in plain words)
- `retrain/train_report.txt` (training output), `model/fresh/RESULTS.md` (the 4-model benchmark, RQ2 offline)
- `docs/results/2026-11-13_pi_lab_v4/RESULTS.md` (old Pi lab), `docs/TinyIDS_Proposal.pdf`, `nextlab.md`
