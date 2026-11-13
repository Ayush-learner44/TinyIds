# Pi lab test, 13 Nov 2026 (branch v4, 7 MB family model)

Setup: Pi 4 = 172.29.2.43 (wlan0, college Wi-Fi IIITA), laptop = 172.29.2.40, NodeMCUs node1 172.29.2.42,
node3 172.29.2.41 (node2 IP not noted). Started with `./run_ids.sh --admin-ip 172.29.2.40`. Dashboard on laptop.

## Results so far
| Test | Result |
|---|---|
| Idle, no sensors (after admin fixes) | 0 alerts |
| 3 NodeMCUs publishing (normal) | 0 alerts for minutes, except low-confidence alerts on node1 (see L4) |
| SYN flood from laptop (~330 pps, 10 s) | DoS flood conf 1.00, BLOCK 172.29.2.40 30 s, auto RELEASED; dashboard stayed live |
| Port scan from laptop (port_scan.py, ports 1-1024, ~200 pps) | named "DoS flood" conf 1.00 (NOT Recon; in Docker nmap -> Recon), BLOCK 30 s; scan saw only 116 answers (rest dropped by the block) |
| Port scan AFTER the fix (new PortScanRule: > 20 ports in 5 s = Recon) | Recon 1.00 by RULE ("different ports: 868"), BLOCK 30 s, no "DoS flood" any more; scan got only 24 answers (blocked within ~1 s). FIXED L8 |
| MQTT brute force from laptop | rule: 5 refused logins in 10 s -> BruteForce 1.00 -> BLOCK; the attacker's 6th try timed out (blocked) |
| node3 during these tests | low-confidence BruteForce 0.54 / Spoofing 0.52-0.62 -> rate-limit (same false-alarm issue as node1) |
| Model time per window | ~2 ms (100-packet windows), ~4 ms (10-packet windows) |
| SHAP time per alert | ~45 ms on flood windows (under 50 ms target), ~95-110 ms on 10-packet windows |
| SYN flood SHAP top-3 | AVG = 54 (bare SYN size), syn_flag_number, Rate |

## 7 MB vs < 1 MB models, measured ON THE PI (benchmark/compare_models.py, 2,000 test windows, one at a time)
| | models/ (live) | models_small/ |
|---|---|---|
| binary / family size | 1,014 KB / 7,032 KB | 974 KB / 776 KB |
| model time per window | 1.88 ms (p95 1.99) | 1.09 ms (p95 1.37) |
| SHAP time per alert | 45.65 ms (p95 46.27) | 2.59 ms (p95 2.63) |
| same family answer as big model | - | 99.2% |
Both meet < 5 ms/window and SHAP < 50 ms on the Pi; the small one also meets < 1 MB and is ~18x faster for SHAP.
BUT in Docker the small model called our bot UDP flood Recon/Spoofing (see START.md) -> fix with own data, then switch.
(Laptop for reference: big SHAP 24 ms, small 1.2 ms.)

## Small (< 1 MB) model LIVE on the Pi (`./run_ids.sh --admin-ip 172.29.2.40 --models models_small`, 14:03-14:07)
| Test | Result (small model) |
|---|---|
| Idle with 3 NodeMCUs, ~1 min | 0 alerts (the big model gave node1/node3 false alarms in the same situation) |
| SYN flood from laptop (282 pps) | DoS flood 1.00, BLOCK 30 s; model 1.2 ms, SHAP 2.7 ms per alert (big model: 45 ms) |
| Bot TCP flood, `bot_master.py tcp_flood --seconds 5` | node3 DoS flood 0.91, node1 "DoS flood (2 senders)" 0.99 -> both QUARANTINED 120 s (sensors cut off: "last seen 57 s"); node2 sent only 20 packets -> not flagged, so no "DDoS (3)"; later node3 10-packet window "Recon 0.93" |
| Bot TCP flood REPEATED 4 times (Flush Bans + Clear between runs, 14:08-14:12) | EVERY run: "DoS flood" -> "DoS flood (2 senders)" -> "DDoS flood (3 senders)", conf 0.93-1.00, all 3 nodes QUARANTINED 120 s; model ~1.25 ms, SHAP ~2.75 ms. Sometimes extra 10-packet "Recon 0.52-0.99" alerts on the bots (their TCP flood opens/closes connections -> RST/ACK flags look like a scan) -> name noise only, response already quarantine |
Conclusion: on the real Pi the small model worked for SYN flood and bot TCP flood, and gave FEWER false alarms at idle.
The Docker failure was the bot UDP flood (not tested live, UDP flood took the Pi offline). Next: test bot UDP flood in Docker
and on a hotspot; if OK, make models_small the live model (meets < 1 MB, < 5 ms, SHAP < 50 ms).

## RAM on the Pi (small model running, after all tests)
`ps -eo rss,args`: TinyIDS python process = **130,760 KB (~128 MB)** -> ABOVE the < 100 MB target (sudo wrappers 6.7 / 2.6 MB).
Likely cause: libraries, not the model (scapy alone ~50-70 MB, plus numpy, lightgbm, paho). Measure at home with
`tracemalloc` / import-by-import; fixes to try: `from scapy.layers...` instead of `scapy.all`, drop unused imports,
sniff with a raw socket or `AsyncSniffer` light config, measure the 7 MB model too.
### RAM analysis at home (13 Nov evening, Docker ids image, same Python code; static RSS after loading)
| Part | RSS added |
|---|---|
| Python | 8.6 MB |
| numpy | +16.6 |
| lightgbm | +33.6 (of which scipy.sparse 26.9 MB, never used by us) |
| paho-mqtt | +0.8 |
| `from scapy.all import ...` | +49.6 (only-needed scapy modules: +38.8) |
| our tinyids code | +0.2 |
| 7 MB models / small models (+1 SHAP call) | +23 / +12 |
Totals: now (scapy.all + 7 MB) 132 MB (Pi live: 128 MB); scapy-light + small 109.5 MB;
scapy-light + small + no scipy 98.2 MB (predictions and SHAP identical, checked on 200 rows).
Live process adds a few MB (threads, flow table) -> must re-measure live in Docker and on the Pi.

### RAM fixes done (13 Nov evening) and LIVE result in Docker (peak = VmHWM of the IDS process)
1. small models are now the default (`pi/models`; old 7 MB ones in `pi/models_big`)
2. `run_tinyids.py` imports only the scapy parts it uses (not `scapy.all`)
3. `tinyids/no_scipy.py`: lightgbm gets an empty scipy stand-in (predictions + SHAP identical)
4. FlowTable and WindowCollector keep at most 2,000 entries (least recently active forgotten first) - floods made
   every packet a "new connection" and RAM grew 98 -> 122 MB
| | before | after 1-3 | after 1-4 |
|---|---|---|---|
| idle | 132 (static) | 98 | 98 |
| after SYN / UDP flood | - | 110 / 122 | 101 / 101 |
| after spoofed SYN + UDP floods (peak) | - | 122 | 110 |
All attacks still detected in Docker after the changes: SYN/UDP flood (DoS 1.00), port scan (Recon by rule 1.00),
brute force (rule 1.00), spoofed floods (IP spoofing), ARP spoofing. Bot UDP flood with the small model: still
"Spoofing 0.5" for all 3 bots (same as before; NOT fixed by these changes).
Pi measured 4 MB less than Docker earlier (128 vs 132) -> expected on Pi ~94 MB idle, ~97 MB after normal floods,
~106 MB peak after spoofed floods. MUST be measured on the Pi.

Not done today: full RQ2 benchmark (`benchmark/rq2_benchmark.py`), energy (no USB meter), UDP flood, spoofing on the Pi.

## Problems found and FIXED in the lab
1. `iptables` not installed on new Raspberry Pi OS -> `sudo apt -o Acquire::http::Proxy=http://172.31.2.3:8080 install -y iptables`.
   (add to setup_pi.sh)
2. Dashboard crashed (`KeyError: 'reason'`): IPS history uses `details`. Fixed in laptop/dashboard.py.
3. Admin laptop's own SSH session -> BruteForce/DoS false alarms and the laptop got blocked. Fixed: `--admin-ip`
   skips the admin's SSH in the capture filter and an iptables ACCEPT keeps port 22 open.
4. Admin's open dashboard MQTT connection (slow trickle) -> "DoS flood 0.96-0.98" and the laptop got blocked, so the
   dashboard went blind. Fixed: admin's MQTT packets WITHOUT SYN are not inspected and are always accepted;
   its SYN floods / UDP / scans / new logins are still inspected and blocked.
7. Port scan was named "DoS flood" by the model -> new PortScanRule in pi/tinyids/rules.py (settings scan_ports=20,
   scan_seconds=5.0); while a sender is scanning, the model's alert for it is ignored. Tested on the Pi: Recon 1.00.
5. Ctrl+C left the DROP rule behind -> dashboard could not reconnect. Fixed: release_all() in a finally block.
6. Pi IP changed (172.29.1.135 -> 172.29.2.43) -> NodeMCUs had the old IP hard-coded -> re-flashed all 3.

## UDP flood: the Pi went OFFLINE (most important open problem)
- `udp_flood.py` from the laptop, port 5683, 285 pps, 10 s (~13:31). TinyIDS logged NO alert, SSH froze, broker
  unreachable (NodeMCUs: `MQTT ... failed (state -2)`), dashboard: broker offline, 0 packets. SYN flood at 311 pps
  just before was fine. So the Pi (or its Wi-Fi link) died at the start of the UDP flood.
- To check: ping after the test; after reboot `dmesg | grep -i brcm` / `journalctl -b -1` (Wi-Fi driver crash?),
  CPU load during a UDP flood (`top`), and whether the Pi answers every UDP packet with ICMP "port unreachable"
  (port 5683 has no server) -> test with a lower rate (`--rate 100`) and with the CoAP port open.
- Possible fixes: lower rate / shorter flood on Wi-Fi, iptables rate-limit UDP before the kernel answers,
  `sysctl net.ipv4.icmp_ratelimit`, Ethernet cable for the Pi instead of Wi-Fi.

## Known limitations to solve at home (Docker testbed)
- L1. Laptop attacks only ~300 packets/s: Python/scapy sends one packet at a time through Npcap (~3 ms each).
  Proposed fix: build packets in advance and send in batches (scapy `sendp(list)` / `L2socket.send` in a tight loop),
  or a `--burst` option; target a few thousand pps. Detection already works at 300 pps (conf 1.00).
- L2. NodeMCU firmware has the Pi IP hard-coded -> re-flash whenever the Pi IP changes.
  Proposed fix: find the Pi by name (mDNS `raspberrypi.local`) or keep the IP in EEPROM / set it over Serial.
- L3. NodeMCU boot / reconnect bursts give low-confidence alerts (BruteForce 0.32, Spoofing 0.53-0.70) -> rate-limit.
  Proposed fix: record our own normal sensor traffic (incl. boot) and add it to training; maybe ignore alerts
  below a minimum family confidence (e.g. 0.5) or need 2 windows for every unsure alert.
- L4. node1 keeps giving occasional "Spoofing 0.64" (10-packet windows) while the others are quiet. Check its
  Wi-Fi signal / reconnects (Serial Monitor), and use the same fix as L3.
- L5. SHAP on 10-packet windows ~100 ms on the Pi (target < 50 ms); flood windows ~45 ms.
  Proposed fix: smaller family model (pi/models_small, SHAP should be much faster) once it is good on our traffic.
- L6. Small (< 1 MB) models not tested on the Pi yet; they were weaker on bot floods in Docker.
- L8. Our scapy port scan (fast SYN to 1,024 ports, ~200 pps) looks like a SYN flood to the model ("DoS flood").
  Proposed fix: a simple rule "one sender touches > N different ports in a few seconds = Recon" (like BruteForceRule),
  or scan slower / with nmap. The response (block) is the same either way.
- L7. setup_pi.sh must install iptables (L-fix 1) and run_ids.sh should take --admin-ip by default.
