# retrain/ results

## Step 1 (16 Nov): Number and Rate in the dataset (validation.csv, kept classes only)

| Attack | Rows | Number (median) | Rate (median) |
|---|---|---|---|
| Benign | 27,519 | 5.5 | 52.5 |
| DDoS / DoS SYN, TCP, PSH-ACK, RST-FIN, ICMP floods | 51k-182k each | **9.5** (all of them) | **1.6 - 13.5** |
| DDoS / DoS UDP flood | 136k / 83k | 9.5 | **7,505 / 10,473** |
| Recon (port scan, OS scan, host discovery) | 2-3.5k each | 13.5 | 17 - 34 |
| Recon ping sweep | 45 | 5.5 | 19.5 |
| Vulnerability scan | 905 | 9.5 | 23.4 |

Most common `Number` values overall: 9.5 (941,397 rows), 13.5 (17,826), 5.5 (17,796).

**Findings**
1. **No sign of 100-packet rows.** Every flood has `Number` ~9.5, the same size as the other rows (their published code
   also uses 10 packets per row). Our "floods = 100-packet windows" assumption is not supported by the data.
2. **`Rate` is unusable.** SYN / TCP / ICMP floods have a LOWER rate (2-13/s) than benign traffic (52/s); only UDP floods
   are high. A model trained on it would learn "high rate = benign" for TCP floods. -> drop `Rate`, no pps feature.
3. `Number` itself (5.5 / 9.5 / 13.5) encodes the window size per class -> a shortcut, stays excluded (as before).

## Step 2 (16 Nov): code changes, only in copies inside `retrain/pi/`
- `tinyids/settings.py`: one window (`window = 10`, `window_timeout = 30.0`), `ddos_sources = 2`.
- `tinyids/windows.py`: one 10-packet window per sender (no 100-packet window).
- `tinyids/features.py`: `Protocol Type` = most common protocol; `Std` with ddof=1 (both like the dataset's script).
- `tinyids/detector.py`: ONE model (`model.txt`, classes from `meta.json`); P(attack) = 1 - P(Benign); SHAP top-3
  towards the attack.
- `run_tinyids.py`: uses the one window and the one model; status sends `model` instead of `binary` / `family`.
- NEW `record.py`: writes feature rows (time, sender IP, all features) to a CSV. No model, no pcap.
- Checked offline (hand-made packets): syntax OK; a window fills at 10 packets; 4 TCP + 6 UDP packets ->
  `Protocol Type` = 17 (most common, was 12.6 as average); Std / Min / Max / flags as expected.
- Not tested yet: the detector with a model (no model trained yet), recording live traffic.
- Originals in `pi/`, `laptop/`, `docs/`, `model/` untouched.

## Step 3 (16 Nov): recorded in Docker (`retrain/testbed/record_all.sh`, files in `retrain/data/`)

| File | Rows | From the attacker | From the sensors (= Benign) |
|---|---|---|---|
| benign (30 min, 10 sensors, 2 restarts) | 1,040 | 0 | 1,040 |
| flood_syn / udp / icmp / ack / pshack / rstfin (30 s, 1000 pkt/s) | 2,621-5,016 each | 2,601-4,996 | 20 each |
| flood_syn_slow (100 pkt/s) | 603 | 583 | 20 |
| recon_connect / syn / os / version (nmap) | 30-63 | 10-43 | 20 each |
| recon_ping (`-sn -PE`) | 20 | **0** | 20 |
| recon_vuln (`--script vuln`) | 21 | **1** | 20 |

Totals: Benign ~1,320 rows, Flood ~18,800, Recon 109.
- SYN flood has ~2x rows: the attacker's system answers every SYN-ACK with a RST (half the packets are RST).
- **Short scans are invisible:** ping sweep and host discovery send < 10 packets to the Pi -> no full window -> 0 rows.
  Same on the live detector (the windows are the same). Port / OS / version scans do fill windows.
- Recon from our side is small (109 rows); most Recon training rows come from the dataset.
- 16 Nov: ping sweep + host discovery dropped from the plan and from training (`train.py` RECON set).

## Step 4 (16 Nov): training (`retrain/train.py`, 72 s, report in `retrain/train_report.txt`)

Data: 923,465 training rows (dataset 20% sample of the kept attacks + 14,097 of ours), validation 197,964, dataset test
973,829, our test 2,965 (190 Benign, 2,767 Flood, 8 Recon).

**Feature ranking (mean |SHAP|):** AVG, ICMP, Protocol Type, Tot size, ack_flag_number, Min, Max, fin_flag_number,
psh_flag_number, TCP, rst_flag_number, syn_flag_number, Std, UDP.

**Mini RQ1 (3 classes):**

| Features | Dataset test macro-F1 | Our test macro-F1 | Our benign rows flagged | Size |
|---|---|---|---|---|
| 5 | 0.686 | 1.000 | 0 of 190 | 974 KB |
| 7 | 0.737 | 1.000 | 0 of 190 | 976 KB |
| 10 | 0.756 | 0.655 (14% of our floods called Recon) | 0 of 190 | 972 KB |
| 14 | **0.762** | 1.000 | 0 of 190 | 974 KB |

**Dataset test, per class (rows = truth, columns = predicted Benign / Flood / Recon):**

| | top 7 | top 14 |
|---|---|---|
| Benign (27,709) | recall 0.989 | recall 0.990 |
| Flood (940,692) | recall 0.996 | recall 0.997 |
| Recon (5,428) | recall **0.236** | recall **0.296** (69% of Recon rows called Benign) |

**Findings**
1. **Benign vs attack is strong:** top 14 on the dataset: 277 of 27,709 benign rows flagged (1.0%); 5,655 of 946,120
   attack rows missed (0.6%) -> attack-class F1 ~0.997, binary macro-F1 ~0.95 (computed from the confusion matrix).
2. **Flood is very strong** (recall 0.997 dataset, 1.0 ours).
3. **Recon is weak on the dataset** (0.24-0.30): with these features the dataset's Recon rows look like normal traffic.
   It is the reason the macro-F1 is only ~0.76. Live, port scans are also caught by the port-scan rule.
4. **Our own traffic: 0 false alarms on 190 benign test rows** for every k. Our scores of 1.000 are optimistic (only 8
   Recon test rows; neighbouring rows of the same 30-s recording sit in train and test) -> the Docker test (step 5)
   with fresh traffic is the real check.
5. The 10-feature model is unstable on our rows (Flood -> Recon); 5 / 7 / 14 are not. With only 109 Recon rows of our
   own, Flood-vs-Recon on our traffic is the fragile part.
6. All models hit the 1 MB cap (~975 KB): more rounds would not fit.
7. Note: the confusion-matrix check accidentally re-ran `train.py` once (an import); same seed, same data -> identical
   models and numbers.

**Chosen: 14 features** (`retrain/pi/models/top14`).

## Step 5 (16 Nov): Docker test of the new detector (`retrain/testbed/test_all.sh`, 19:22-19:49)

New detector (`retrain/pi`, top14 model, IPS on) + 10 sensors + attacker + dashboard (localhost:8502).
Every attack ran 20 s; alerts are at most 1 per second per sender (alert filter), so 20 alerts = alerted all 20 s.

| Phase | Alerts | Name, confidence | Top-3 SHAP reasons |
|---|---|---|---|
| **1. normal traffic, 10 min, 10 sensors** | **0** | — | — |
| SYN flood (hping3 -S) | 20 | DoS flood 1.00 -> blocked | ack_flag_number, AVG, Min |
| UDP flood (--udp) | 20 | DoS flood 1.00 | UDP, AVG, Protocol Type |
| ICMP flood (--icmp) | 20 | DoS flood 1.00 | ICMP, AVG, ack_flag_number |
| ACK flood (-A) | 20 | DoS flood 0.99 | AVG, Min, Tot size |
| PSH-ACK flood (-PA) | 20 | DoS flood 1.00 | psh_flag_number, AVG, Min |
| RST-FIN flood (-RF) | 20 | DoS flood 1.00 | fin_flag_number, ack_flag_number, AVG |
| port scan nmap -sT | 20 | **Recon 0.95-1.00** (model) | AVG, Tot size, Protocol Type |
| port scan nmap -sS | 20 | Recon 1.00 | AVG, Max, Tot size |
| OS scan nmap -O | 20 | Recon 1.00 | AVG, Max, Tot size |
| bots UDP flood (10 sensors) | 167 | **DDoS flood (10 senders) 0.94**, all 10 quarantined | Protocol Type, UDP, ack_flag_number |
| bots TCP flood (10 sensors) | 170 | **Recon 0.53-0.99** (wrong name), all 10 still blocked / quarantined | AVG, Tot size, Protocol Type |
| **5. normal traffic, 5 min** | **4** (all node8, in the first 90 s) | Recon 0.83-0.96, DoS 0.59 | — |

IPS actions: 9 block, 11 quarantine, 2 rate-limit, 22 released (all ran out by themselves).

**Findings**
1. **0 false alarms in 10 min of normal traffic from 10 sensors**, which the new detector now judges (with the old
   detector their traffic was never judged at all).
2. **All 6 hping3 flood types caught at 0.99-1.00**, with sensible reasons (UDP flood -> `UDP`, ICMP -> `ICMP`,
   PSH-ACK -> `psh_flag_number`, RST-FIN -> `fin_flag_number`).
3. **All 3 nmap scans named Recon by the MODEL at 0.95-1.00** (old model on 16 Nov: Recon only through the rule).
4. **Bot UDP flood = DDoS (10 senders)**, all quarantined (the DDoS rule with 2+ senders works).
5. **Problem: the bots' TCP flood is named "Recon", not Flood.** The bots open and close full TCP connections to ONE port;
   an `nmap -sT` scan also opens and closes connections, just to MANY ports. Without port numbers the model can't tell
   them apart. The bots were still blocked (every Recon alert is acted on), only the name is wrong. We recorded no bot
   TCP flood for training. Fix: record the bot TCP flood as Flood rows and retrain (~5 min recording + 1 min training).
6. **Leftover alerts on node8** for ~90 s after the bot attack: node8 was quarantined, and while blocked its MQTT
   client kept retrying the connection (repeated SYNs) -> looked like Recon. After that, 3.5 min clean.
7. (see the fix below) The old detector (pi/, same day) on the old testbed: bot floods gave extra "Web" / "Recon" / "Spoofing" alerts from
   the 10-packet windows. The new one: no "Web" / "Spoofing" at all (those classes no longer exist).

## Step 5 fix (16 Nov): bot TCP flood

**a) Recorded the bot floods as Flood rows** (`testbed/record_bots.sh`, detector stopped, recorder only WHILE the
10 sensors flood): `flood_bots_tcp_1..3` (~5,000 rows each), `flood_bots_udp_1` (6,523 rows). `train.py` labels
`flood_bots_*` rows as Flood. Retrained (same script):

| Features | Dataset test macro-F1 | Our test macro-F1 | Our benign rows flagged |
|---|---|---|---|
| 5 | 0.716 | 0.957 | 0 of 188 |
| 7 | 0.725 | 0.957 | 0 of 188 |
| 10 | 0.743 | 0.957 | 0 of 188 |
| **14 (used)** | **0.763** | **0.990** | **0 of 188** |

**b) Re-test** (`testbed/test_bots.sh`): normal 3 min **0 alerts**; nmap -sT / -sS / -O **Recon 0.98-1.00** (still
Recon, not Flood); bot UDP flood **DDoS flood (10 senders)** 137 of 148 alerts; normal 3 min after **0 alerts** (no
node8 leftovers). Bot TCP flood: the FIRST alerts were right (within 1 s: DoS -> DDoS flood (2 ... 10 senders), 0.97-1.00,
all 10 quarantined), but then 166 "Recon" alerts followed: they came AFTER the quarantine. A blocked bot only sends
connection retries (SYNs that get no answer), which look like a scan.

**c) Fix in `retrain/pi/run_tinyids.py`:** a sender that is already blocked / quarantined is not classified again
(it is already handled; rate-limited senders are still checked, they may need a stronger action). Re-test
(`testbed/test_bots_tcp.sh`): **10 alerts in total, all Flood (DoS -> DDoS 2 ... 10 senders) within 1 s, all 10
quarantined, all released after 120 s, 0 alerts in the 3 min after.**

## Summary after step 5 (Docker)

Measured working in Docker with the new detector (14 features, one 3-class model):
- **Floods (model + sender count):** hping3 SYN, UDP, ICMP, ACK, PSH-ACK, RST-FIN floods (0.99-1.00); bot UDP and
  TCP floods from 10 senders -> DDoS, quarantined.
- **Recon (model):** nmap -sT, -sS (port scans), -O (OS scan): 0.95-1.00.
- **Normal traffic from 10 sensors: 0 false alarms** (16 min of quiet phases in total).
- Not tested in this step: vulnerability scan live, brute force rule, ARP spoofing rule (rules unchanged).
- Still to do: the real Pi + real NodeMCUs (lab).

## Lab 17 Nov: real NodeMCU benign recording + retrain
- Recorded on the Pi (`record.py`, 20 min, 3 NodeMCUs with `nodemcu_sensor_plain.ino`, 1 reading / 0.2 s):
  **1,634 rows** (492 / 592 / 550 per board) -> `training/data/benign_plain.csv`.
- Retrained (`training/train.py`, 69 s): our benign rows now 2,934 (Docker 1,300 + real 1,634).

| Features | Dataset test macro-F1 | Our test macro-F1 | Our benign test rows flagged |
|---|---|---|---|
| 5 | 0.691 | 0.972 | 0 of 448 |
| 7 | 0.740 | 0.981 | 0 of 448 |
| 10 | 0.758 | 0.674 (floods -> Recon again, unstable) | 0 of 448 |
| **14 (used)** | **0.763** | **0.983** | **2 of 448** |

## Lab 17 Nov: real attack recordings + retrain
- Recorded on the Pi WITHOUT admin while the laptop (172.29.2.52) attacked from WSL (`attack_all.sh ... floods|scans`):
  `flood_lab.csv` 4,616 laptop rows (4,268 kept, pps >= 20) + 454 NodeMCU rows (Benign);
  `recon_lab.csv` 443 laptop rows (135 kept) + 359 NodeMCU rows. UDP and ICMP floods ran only 4 s / 2 s (WSL "Network
  is unreachable" again); SYN, ACK, PSH-ACK, RST-FIN ran 15 s each.
- Retrained (70 s). Our rows: Benign 3,747, Flood 44,568, Recon 244. CICIoT2023 is still ~96% of the training rows.

| Features | Dataset test macro-F1 | Our test macro-F1 | Our benign test rows flagged |
|---|---|---|---|
| 5 | 0.642 | 0.891 | 0 of 558 |
| 7 | 0.710 | 0.953 | 0 of 558 |
| 10 | 0.754 | 0.700 (unstable again) | 0 of 558 |
| **14 (used)** | **0.762** | **0.981** (Flood 0.999, Recon 0.947) | **1 of 558** |

## Lab 17 Nov: status of the planned attacks (during the final run, RAM 78 MB with attacks)

| Planned | Status on the real Pi |
|---|---|
| DoS floods (SYN, UDP, ICMP, TCP/ACK, PSH-ACK, RST-FIN) | tested from the laptop, recorded and trained |
| DDoS floods (same, 2+ senders) | NOT tested on the real Pi yet (needs the bot firmware; worked in Docker) |
| Port scan | tested, recorded and trained |
| Vulnerability / version scan | version scan tested and recorded |
| OS scan (`nmap -O`) | NOT run (needs sudo password) |
| MQTT brute force | rule works |
| ARP spoofing | NOT tested |
| Benign with text notes | NOT recorded (optional; plain benign works) |

## Lab 17 Nov: FINAL live test after the retrain (attack_all.sh, fresh attacks, IPS ON, 3 NodeMCUs running)

Logs: `laptop/attack_log_1446.txt`, `laptop/dashboard_alerts_1446.txt` (+ the Pi's `lab_log2.txt`). RAM 78 MB.

| Attack | Alert | Confidence | Top-3 SHAP reasons |
|---|---|---|---|
| normal traffic (60 s before, 60 s after) | **none** | | |
| SYN flood | **DoS flood** (was "Recon" before the retrain) | 0.968 | Min, syn_flag_number, Std |
| UDP flood | DoS flood | 0.999 | Min, Protocol Type, UDP |
| ICMP flood (ran 6 s, WSL glitch) | DoS flood | 0.999 | ICMP, Min, ack_flag_number |
| ACK flood | **DoS flood** (was missed before the retrain) | 0.979 | Min, Max, Std |
| PSH-ACK flood | DoS flood | 1.000 | psh_flag_number, Min, Max |
| RST-FIN flood | DoS flood | 1.000 | Min, fin_flag_number, rst_flag_number |
| port scan | Recon (model) + Recon (port-scan rule) | 0.992 / 1.0 | AVG, Tot size, Protocol Type |
| version scan | Recon (model) | 0.992 | AVG, Tot size, Protocol Type |
| MQTT brute force | BruteForce (rule) | 1.0 | refused MQTT logins |

**12 alerts, all correct, 0 false alarms on the 3 NodeMCUs for the whole run** (no node alerts at all; the node3 loop
is gone). Every attack was blocked for 30 s.

## Lab 17 Nov: real bot floods (3 NodeMCUs, bot firmware) + retrain
- First live DDoS test (model before this retrain): bot UDP flood -> DoS -> DDoS flood (2 -> 3 senders), 0.90-1.00,
  all 3 quarantined. Bot TCP flood -> DDoS flood (3 senders) but only 0.58-0.74 (2 bots only rate-limited).
  College Wi-Fi drops UDP broadcast: `bot.py` now also takes the bot IPs and sends the command to each one.
- Recorded on the Pi (IDS off) WHILE the bots flooded: `flood_bots_lab_tcp1..3.csv` (746 / 790 / 923 rows),
  `flood_bots_lab_udp1.csv` (843 rows; node3 sent ~267,000 UDP packets in 30 s). All bot rows = Flood; the laptop's
  few SSH rows are dropped.
- Grace period after a quarantine: 30 s, only when it runs out by itself (not after Flush Bans).
- Retrained (61 s), top 14: dataset test 0.760, our test 0.957 (Flood 0.999, Recon 0.875 on 39 rows), 1 of 567
  benign test rows flagged.
- **Live test after this retrain:** bot TCP flood -> DoS -> DDoS flood (2 -> 3 senders), **0.96-0.97**, **all 3
  quarantined** within 1 s (before: 0.58-0.74, 2 bots only rate-limited).
- Bot UDP flood (same model): DoS -> DDoS flood (2 -> 3 senders), **1.00**, all 3 quarantined within 1 s.
- Note: `bot.py` sometimes prints "no bot answered" although the bots DO attack (seen on the Pi). The bots' replies
  get lost (most often during the UDP flood, when the Wi-Fi is saturated). Cosmetic; the command itself arrives.
- Problem seen: stopping `./run_ids.sh ... | tee log` with Ctrl+C kills `tee` first; the IDS then crashes
  (BrokenPipeError) while removing its blocks, so old iptables DROP rules stay behind. The blocked NodeMCUs keep
  retrying MQTT (SYN / RST) and the new IDS flags them as floods. Fix: `sudo iptables -F INPUT`, and start with
  `tee -i` (tee ignores Ctrl+C). After that: no alerts with only the NodeMCUs running.

## Lab 17 Nov: FINAL run with the FINAL model (after the bot-flood retrain), Pi log `laptop/lab_logs_17nov/lab_log4.txt`

| Attack (laptop, one sender) | Alert | Confidence | Top-3 SHAP reasons |
|---|---|---|---|
| normal traffic 60 s before / after (3 NodeMCUs on) | none | | |
| SYN flood | DoS flood | 0.96 | Min, Std, ack_flag_number |
| UDP flood | DoS flood | 1.00 | Protocol Type, Min, UDP |
| ICMP flood | DoS flood | 1.00 | ICMP, Min, ack_flag_number |
| ACK flood | DoS flood | 0.98 | Min, Max, Std |
| PSH-ACK flood | DoS flood | 1.00 | psh_flag_number, Min, Max |
| RST-FIN flood | DoS flood | 1.00 | fin_flag_number, Min, rst_flag_number |
| port scan | Recon (model) + Recon (port-scan rule) | 0.99 / 1.00 | AVG, Tot size, Max |
| version scan | Recon (model) | 0.99 | AVG, Tot size, Max |
| MQTT brute force | BruteForce (rule) | 1.00 | refused MQTT logins |
| OS scan (`sudo nmap -O`, extra, by hand) | DoS flood (wrong name, but blocked at once) | 0.96 | Min, Std, syn_flag_number |

Bots with the same model (same session): TCP DDoS 0.96-0.97 and UDP DDoS 1.00, all 3 quarantined.
**Every attack detected and blocked; no false alarms on the 3 NodeMCUs.** Not tested: ARP spoofing.
The Pi's clock is ~1 h 12 min behind the laptop (laptop 15:51 = Pi 14:38).

## Lab 19 Nov: ARP spoofing on the real Pi (IIITA Wi-Fi)

Attack (laptop, WSL): `python3 launch.py 172.29.3.125` -> 7 -> pretend to be node1 (`172.29.1.253`), i.e.
`sudo arpspoof -i eth1 -t 172.29.3.125 172.29.1.253` for 10 s. Check on the Pi at the same time:
`sudo tcpdump -n -i wlan0 arp and host 172.29.1.253`.

| | MAC in the ARP reply |
|---|---|
| sent by the laptop (arpspoof output, 5 replies) | `2c:98:11:80:93:63` (the laptop: the fake claim) |
| received by the Pi (tcpdump, 5 replies, 17:19:42-46, same seconds) | `bc:dd:c2:16:1e:bc` (node1's real MAC) |

**Result:** the college access point **rewrites spoofed ARP replies** on the way: the Pi only ever received the
correct "node1 is at node1's MAC". The Pi's ARP table was never poisoned, and TinyIDS correctly raised **no alert**
(there was nothing wrong to see). So ARP spoofing **cannot be tested on the IIITA Wi-Fi**; the network itself stops
it before it reaches the gateway. The AddressWatcher rule was tested in Docker (13 Nov). A real-hardware test needs
our own Wi-Fi (e.g. a phone hotspot with the Pi, laptop and NodeMCUs re-flashed for it).

**Report sentence:** "ARP spoofing: the rule was tested in Docker. On the college Wi-Fi the access point rewrites
spoofed ARP replies, so the attack never reaches the gateway (verified with tcpdump on the Pi)."
