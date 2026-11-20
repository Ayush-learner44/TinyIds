# My part: "Edge deployment and active defense (IPS) on the Raspberry Pi gateway"

In one line: *"I took the trained model out of the lab notebook and made it protect a real IoT network: Raspberry Pi gateway,
real NodeMCU sensors, live attacks, automatic blocking, and a live dashboard."*

Why this part:
- **It sounds big:** edge deployment, intrusion *prevention*, botnet quarantine, ARP spoofing detection, firewall automation, real hardware.
- **The code is easy:** the rules are plain if/else and counting (`rules.py`, `address_watcher.py`, `response.py`, each about 100 lines).
- **I can prove it:** live demo, screenshots, measured numbers from the lab.
- **It's genuinely mine:** the lab, the Pi, flashing the NodeMCUs, the mitigation idea, the test results.

---

## 1. The 1-minute explanation (memorize this)

> "A machine-learning model can say *'this traffic looks like an attack'*, but on its own it doesn't stop anything, and it
> can't see some attacks at all. My part makes the gateway **act**.
>
> The Raspberry Pi captures every packet coming in. It groups them into windows of 10 or 100 packets per sender and turns
> each window into 30 numbers (features). The model says *attack or not*, and *which family*.
>
> Then my response engine decides what to do: block an outside attacker for 30 seconds, quarantine one of our own sensors
> for 2 minutes if it has become a bot, or just slow a sender down if the model isn't sure. These are real Linux firewall
> (iptables) rules, so the kernel drops the packets.
>
> Next to the model I added simple rules for attacks the model can't see: brute-force logins, port scans, ARP spoofing,
> and floods with fake source IPs. I tested everything on a real Pi with 3 real NodeMCU sensors that I turned into a botnet."

---

## 2. The folders and files, and the job of each

### `pi/`: everything in it is copied to the Pi (into `~/tinyids/`)

| File / folder | What it is |
|---|---|
| `setup_pi.sh` | **Run once** on a fresh Pi: makes the Python environment (`venv`), installs mosquitto, scapy, lightgbm... |
| `run_ids.sh` | **What you type every time**: `./run_ids.sh admin <laptop ip>`. Starts the broker, turns on SYN cookies, then starts `run_tinyids.py` |
| `run_tinyids.py` | **The main program.** Captures packets and passes each one through the parts in `tinyids/` |
| `tinyids/` | **The parts** the main program uses (table below) |
| `broker/tinyids_broker.conf` | Settings of our MQTT broker (port 1884, password) |
| `models/` | The small (< 1 MB) models, the default |
| `models_big/` | The old 7 MB models, only for comparison |
| `benchmark/` | Speed / size / RAM tests that run on the Pi (`rq2_benchmark.py`, `compare_models.py`) + their test data (`bench_data.npz`) and test models |

Pi options are plain words, no dashes: `admin 172.29.2.40`, `models models_big`, `noips`, `shap 80`.

### Why `tinyids/` has so many files
It is ONE program split into small files, **one job per file**, so each file is short (25-160 lines) and easy to explain.
In one file, `run_tinyids.py` would be over 1,000 lines. A packet goes through them in this order:

| Order | File | Job (one line) |
|---|---|---|
| 1 | `windows.py` | Collects packets per sender into groups of 10 and 100 |
| 2 | `features.py` | Turns a group into the 30 numbers the model needs |
| 3 | `detector.py` | Runs the 2 models (attack? which family?) + SHAP |
| 4 | `alert_filter.py` | Stops alert spam; unsure alerts must repeat |
| 5 | `rules.py` | Brute force, port scan, DoS/DDoS sender counting |
| 6 | `address_watcher.py` | ARP spoofing + fake-IP floods (does the IP fit the MAC?) |
| 7 | `response.py` | Firewall: block / quarantine / rate-limit (iptables) |
| 8 | `publisher.py` | Sends alerts and stats to the dashboard over MQTT |
| - | `settings.py` | **All numbers in one place** (thresholds, 30 s block, 20 packets/s...) |
| - | `stats.py` | Counts packets / alerts for the dashboard |
| - | `no_scipy.py` | RAM trick: stops lightgbm from loading scipy (saves ~27 MB) |
| - | `__init__.py` | Empty; tells Python "this folder is a package" |

### `laptop/`: runs on the laptop

| Item | What it is |
|---|---|
| `nodemcu_bot/nodemcu_bot.ino` | Firmware you **flash** onto the 3 NodeMCUs (Arduino IDE, USB): a sensor that becomes a bot on command |
| `testbed/` | **Docker only**: a fake Pi, 3 fake sensors (`sensors/sensor.py`, a Python copy of the `.ino`) and an attacker, all on the laptop |
| `dashboard.py` | The Streamlit dashboard (`streamlit run laptop/dashboard.py -- <PI_IP>`) |
| `launch.py` | **All attacks in one menu**: `python launch.py <PI_IP> [seconds] [number]` (1-7 attacks, 8 bots, 9 all) |
| `bot.py` | **Commands the bots**: `python bot.py udp 10` / `tcp 10` / `stop` |

`model/` = training (incl. `make_bench_data.py`: run once on the laptop to put 20,000 test rows + compressed models
into `pi/benchmark/`, because the Pi does not have the dataset).

### How the bot master talks to the bots (UDP broadcast)
- The laptop sends **one UDP broadcast packet** (to 255.255.255.255, port 6667) with the text `udp 10`.
  Every device on the Wi-Fi receives it; only our bots listen on port 6667. **No bot IP is needed.**
- The command does **not** go through the Pi's broker. (Before 15 Nov the bots took orders from a `cmd/bot` topic on
  the Pi's own broker: unrealistic, and a hole anyone with the sensor password could use. Removed.)
- Like Mirai: the attacker controls the bots from **its own machine** ("C2" = Command and Control server).
  Mirai uses TCP; we use UDP broadcast because it is simpler and needs no IP in the firmware.
- The bot answers back to the laptop by UDP ("node1: udp flood started"). What it attacks is fixed in the firmware:
  only the Pi, at most 30 s.
- How the command arrives and what the bot floods with are separate: the command is just a word, the flood is a loop
  in the firmware (UDP: `udp.beginPacket/write/endPacket`; TCP: `connect` + `stop`). No hping3: the NodeMCU has no OS.

## 3. Why each decision (the "why" questions)

- **Why IPS and not just IDS?** An alert at 3 a.m. that nobody reads protects nothing. Blocking is automatic and expires by
  itself, so a mistake costs at most 30 seconds.
- **Why three actions?** Punishment matches certainty. Sure → block. Our own sensor → quarantine (longer, because the device
  is compromised). Unsure → rate-limit, which slows an attacker but doesn't cut a real user off.
- **Why rules next to ML?** Use the right tool for each job. A brute force is literally "5 wrong passwords"; you don't need
  AI for that, and a rule never guesses. ML handles what has no simple rule, like the patterns of floods and scans.
- **Why on the Pi (edge) and not the cloud?** It reacts in milliseconds, keeps working without internet, and sends no private
  sensor data anywhere.
- **Why expiry instead of permanent bans?** False alarms happen. Temporary bans keep a mistake cheap.
- **Why DoS vs DDoS by counting?** Without the timing feature (IAT), the model can't tell them apart (shown in training).
  Counting the senders flooding at the same moment *is* the definition of DDoS.

---

## 4. Numbers to quote (all measured on the real Pi, 13 Nov 2026)

- SYN flood → **detected at confidence 1.00 within about 1 s**, laptop blocked, auto-released after 30 s
- **3 NodeMCU bots** → "DDoS flood (3 senders)" → **all 3 quarantined, 4 runs out of 4**
- Port scan → Recon (rule) → blocked; the scan got only 24 answers out of 1,024 ports
- Brute force → blocked after 5 wrong passwords; the attacker's 6th try timed out
- Model: **< 1 MB**, **about 1.1 ms per window**, SHAP **2.6 ms** (targets: < 5 ms and < 50 ms)

(All details: `docs/results/2026-11-13_pi_lab_v4/RESULTS.md`)

---

## 5. Limitations, and the honest answer to each

| Limitation | My counter |
|---|---|
| Detection uses a dataset from another lab (CICIoT2023), so some normal sensor traffic gives low-confidence alerts | That's why unsure alerts only rate-limit and need to repeat. Fix: record our own normal traffic and retrain |
| The attacker can change its IP | Fake-IP floods are caught by MAC address (one MAC, many IPs), and the MAC gets blocked |
| MAC rules only work inside the local network | True, and the gateway protects exactly that local IoT network |
| Python/scapy limits capture to about 1,000-5,000 packets/s | Enough for an IoT gateway; a huge flood would need kernel-level filtering (XDP), which is future work |
| A UDP flood once made the Pi lose Wi-Fi | Under investigation; the next test uses Ethernet/hotspot and watches the network log |
| RAM was 128 MB (target < 100 MB) | Reduced in code to about 98 MB idle in testing; must be confirmed on the Pi |
| Attacker blocked for only 30 s | It's re-blocked the moment it attacks again; short bans keep false alarms cheap |

---

## 6. Questions the professor may ask

- **"What exactly did you write?"** → The gateway side: capture, windows, the response engine, the rules, the hardware
  testbed, and the tests. *"I used AI tools to help write code, then tested and fixed it on real hardware myself."*
  Being honest about AI is fine; he already knows.
- **"What is iptables?"** → The Linux firewall built into the kernel. A rule like *"drop everything from IP X"* stops packets
  before any program sees them.
- **"What is SHAP?"** → A method that tells how much each feature pushed the model toward its answer. We show the top 3.
- **"Why LightGBM?"** → Small, fast, accurate on tables of numbers, and SHAP for trees is exact and fast.
  (The fresh comparison table `model/fresh/RESULTS.md` backs this up.)
- **"What's a false positive, and how do you handle it?"** → Normal traffic flagged as an attack. We use confidence
  thresholds, repetition for unsure alerts, gentle actions when unsure, and auto-expiry.
- **"What happens if the IDS blocks the router?"** → It can't: the router and the gateway are on a never-block list.
- **"Is this a real botnet?"** → It's a simulated botnet: our own NodeMCUs take commands over MQTT, like Mirai does, but with
  no real malware. The safest way to test.

---

## 7. Demo script (5 minutes)

1. Dashboard: 3 sensors live, 0 alerts.
2. SYN flood → the alert and the SHAP chart appear → "Blocked" → it disappears after 30 s.
3. `python launch.py <PI_IP> 5 8` → `tcp` (or `python bot.py tcp 5`) → DDoS (3 senders) → 3 sensors quarantined.
4. Brute force → blocked after 5 tries.
5. Close with the numbers table.

---

## 8. My questions on the pipeline, CICFlowMeter, nmap, SHAP, hping3 (15 Nov)

**Q: Why don't we use CICFlowMeter? Is it different software? Is it simpler/faster than scapy?**
- Yes, separate software: a **Java** program from CIC (the lab that made the dataset). It turns traffic into
  "flows" (one connection start to end, ~80 numbers). A Python copy also exists on pip.
- Not used, 3 reasons:
  1. **Its features don't match our model.** CICIoT2023's 46 features were NOT made with CICFlowMeter; the authors
     used their own tool on windows of 10 / 100 packets. CICFlowMeter would give the model different numbers.
  2. **Slow to alert.** A flow only ends when the connection closes or times out (seconds to 2 minutes), so the
     alert waits. We decide every 10 or 100 packets.
  3. **Heavy on the Pi** (Java, bad for < 100 MB RAM).
- scapy is only our packet **capture** (like Wireshark, in Python). The feature maths is our own `pi/tinyids/features.py`.
- The proposal itself says "CICFlowMeter **or** a lightweight scapy-based extractor": we chose the second.

**Q: What is nmap?**
A **network scanner**: knocks on a machine's ports to find which are open and what programs run behind them.
`nmap -sS -p 1-1024 <PI_IP>` = send a SYN to ports 1-1024 = the "port scan" attack.

**Q: Where is the ML? Between publisher and broker, or broker and subscriber?**
**Neither. It is not in the MQTT path at all.** MQTT messages flow normally. The IDS **listens to a copy** of every
packet that reaches the Pi's Wi-Fi card (any kind: TCP, UDP, ICMP), like Wireshark:
```
packet arrives at the Pi's Wi-Fi card --> broker gets it normally (MQTT works as usual)
              | (copy)
              v
  windows -> 30 features -> ML model -> alert + SHAP -> iptables block (in the kernel, in front of the broker)
                                          |
                                          v
                       IDS publishes the alert to the broker -> dashboard (a subscriber)
```
ML **watches**, the firewall **blocks**, the broker only **carries alerts** to the dashboard.

**Q: Why "simple SHAP" and not TreeSHAP?**
**We DO use TreeSHAP.**
- On the Pi: LightGBM's built-in TreeSHAP, `predict(..., pred_contrib=True)` (`pi/tinyids/detector.py`). Same exact
  maths, without importing the `shap` library (saves RAM and time). ~2.6 ms per alert on the Pi.
- On the laptop (feature ranking, RQ1): the `shap` library's `TreeExplainer` (`model/train_tinyids.py`) = also TreeSHAP.

**Q: Does hping3 make only SYN floods, or TCP and UDP too?**
All of them:
- SYN flood: `hping3 -S -p 1884 --flood <PI_IP>`
- UDP flood: `hping3 --udp -p 5683 --flood <PI_IP>`
- spoofed (fake source IPs): add `--rand-source`
- ICMP flood: `hping3 -1 --flood <PI_IP>`

**Q: Can I attack directly with hping3 + nmap instead of scripts? (idea for later, nothing changed yet)**
- **nmap**: normal Windows installer, works with the Npcap we already have.
- **hping3**: no working Windows version. Run it in **WSL (Ubuntu inside Windows)** with "mirrored networking",
  so the packets leave from the laptop's real IP.
- Careful: `--flood` = tens of thousands of packets/s (285/s already knocked the Pi off once).
  Use a fixed rate instead: `-i u1000` = 1,000 packets/s.
- They **can't** do: MQTT brute force (still `launch.py` 4), ARP spoofing (needs `arpspoof`), the bots (`bot.py`).
- In Docker, the attacker container already uses hping3 and nmap.

---

## 9. How the IDS gets the packets, the SSH false alarm, why port scans matter (15 Nov)

**Q: Is every packet reaching the Pi checked by the ML? How is it taken from the OS? Port sniffing? os module?**
- Neither. It is **packet capture through libpcap** (the library under Wireshark / tcpdump).
- File: **`pi/run_tinyids.py`**, line ~207:
  `sniff(iface=self.settings.interface, filter=self.capture_filter(), prn=self.on_packet, store=False)`
  - `sniff(...)` = scapy's capture. Underneath it opens a **raw packet socket** on `wlan0`; the Linux kernel gives it
    a **copy** of every frame the Wi-Fi card receives (taken at the driver, BEFORE the IP/TCP stack and iptables).
  - `filter=...` = a **BPF filter** (`capture_filter`, line ~187), runs **inside the kernel**, so unwanted packets
    never reach Python. Keeps: packets TO the Pi + the broker's login answers; minus the admin laptop's SSH and its
    open dashboard connection.
  - `prn=self.on_packet` = for every copied packet, scapy decodes it and calls `on_packet`.
  - That is why `run_ids.sh` uses `sudo`: a raw packet socket needs root.
- The original packet **goes on unchanged** to the IP stack, iptables, the broker. The IDS is a **watcher, not a gate**.
- The model does NOT check every packet: each packet only **updates counters** of its sender's window; the model runs
  **once per full window** (10 or 100 packets of one sender), max 25 times/s per sender.
- The ML never decides pass/drop per packet: alert -> `response.py` adds an **iptables rule** -> the **kernel** drops
  that sender's next packets.

**Q: Who does the extraction? Does scapy do everything?**
No, scapy does 2 of the 4 steps:
| Step | Who | Where |
|---|---|---|
| 1. Copy packets from the Wi-Fi card (+ kernel BPF filter) | **libpcap / Linux kernel**, opened by scapy's `sniff()` | `run_tinyids.py` |
| 2. Decode bytes into fields (IP src, TCP flags, ports, length) | **scapy** (`packet[IP].src`, `packet[TCP].flags`...) | `features.py` (`PacketReader`) |
| 3. Group per sender into windows of 10 / 100 packets | **our code** | `windows.py` |
| 4. Compute the 30 features (averages of flags, sizes Min/Max/AVG/Std, rate, protocol...) | **our code** (numpy) | `features.py` (`FeatureBuilder`) |
scapy = capture + decode. The features (what the model needs) are our own maths, written to match how the dataset
authors computed them.

**Q: Is that why my SSH got flagged?**
Yes. Before the `admin` option, my SSH session went into the same capture. Every keystroke / screen update is a small
TCP packet with PSH/ACK flags. The model never saw "normal SSH" (the dataset's normal traffic is IoT devices), and those
windows looked like the dataset's BruteForce/DoS patterns -> my laptop was flagged and blocked. Now the BPF filter skips
my SSH (port 22) in the kernel.

**Q: What is the harm in a port scan? Let them scan.**
On its own: **nothing breaks.** It is **reconnaissance**, step 1 of an attack, like a burglar checking which doors are
unlocked. What the attacker learns:
| Open port found | What they do next |
|---|---|
| 22 (SSH) | Guess passwords (`pi` / `raspberry` is the classic) |
| 1884 / 1883 (MQTT) | Brute-force the broker; if no password: read or **inject fake sensor data** |
| 23 (Telnet) | **Exactly how Mirai spread**: scanned the internet for open Telnet, logged in with default passwords |
| 80 / 8080 (web panel) | Default admin logins |
With `nmap -sV` it also learns **program versions** (e.g. "Mosquitto 2.0.11") and looks up **known vulnerabilities**.
Why block it: the scan is the **early warning**. Block the attacker while they are "looking around" and they never get
the map for the real attack. That is why CICIoT2023 has a whole **Recon** class.
Honest limit: blocking scans does not make an open service safe; strong passwords and closing unused ports still matter.

---

## 10. MQTT login, SYN cookies, port 5683, all clients and topics (15 Nov)

**Q: Do we need an ID and password to connect / publish / subscribe?**
Yes, on OUR broker (port 1884): `allow_anonymous false` in `pi/broker/tinyids_broker.conf`, password made by
`pi/setup_pi.sh` step 5 (`mosquitto_passwd ... tinyids tinyids123`). No login = no connection at all.
After login, any topic can be published / subscribed (no ACL). Everyone uses the same login `tinyids` / `tinyids123`
(weak spot: one stolen password = also the dashboard's buttons; fix = separate users + ACL).
MQTT without a password = anyone publishes / subscribes anything = fake data injection. That is why the lock exists,
and MQTT brute force = guessing that password.

**Q: Which queue does a SYN flood fill? How do SYN cookies work?**
The **kernel's SYN queue** for the port (not the broker). Size: a few hundred to ~1,000 entries
(check on the Pi: `sysctl net.ipv4.tcp_max_syn_backlog net.core.somaxconn`). Full queue = new SYNs dropped =
a sensor that reconnects can't get in. Connected sensors keep working.

Normal handshake: the kernel REMEMBERS every half-open connection.
```
 client                         Pi kernel
   | ---- SYN ------------------> |  stores an entry in the SYN queue (waits up to ~30-60 s)
   | <--- SYN-ACK --------------- |
   | ---- ACK ------------------> |  entry -> real connection -> broker gets it
 attacker: sends only SYNs, never the ACK -> 1,000 entries -> queue full -> real sensors refused
```
**There are TWO queues per port (this is the key):**
```
                    Pi kernel, port 1884
 SYN arrives --> [ SYN queue    ]  half-open: "got SYN, sent SYN-ACK, waiting for ACK"   <- the flood fills THIS
 ACK arrives --> [ accept queue ]  finished connections, waiting for the broker to pick them up
                        |
                        v
                 broker (Mosquitto) takes it -> a normal open connection (no queue any more)
```
The attacker never sends the ACK, so only the **SYN queue** fills. The accept queue stays almost empty.

**SYN cookies = skip the SYN queue.** When it is full, the kernel does not store the half-open connection anywhere.
Instead it puts the information into the SYN-ACK itself, in the **sequence number** (a 32-bit number every TCP packet
carries). That number is the "cookie":
`cookie = hash(secret key, client IP, client port, Pi IP, Pi port, time slot)` (the time slot changes every 64 s).

**Why the client sends back cookie + 1 (and why the hash still works):**
In TCP the ACK number is ALWAYS "the other side's sequence number + 1". It means "I got your packet number X, send me
X+1 next". Every TCP connection on earth does this; the client does not know it is a cookie.
The kernel does NOT hash the +1 value. It first **subtracts 1** to get the cookie back, then **recomputes** the hash
from the ACK packet's own IPs and ports, and compares the two.

**Example with numbers** (sensor 172.29.2.42, port 51000 -> Pi 172.29.2.43, port 1884, queue full, cookies on):
```
 1. sensor -> Pi : SYN
 2. Pi computes  : hash(secret, 172.29.2.42, 51000, 172.29.2.43, 1884, slot 7) = 3,000,000,000
                   stores NOTHING
 3. Pi -> sensor : SYN-ACK, sequence number = 3,000,000,000            (the cookie)
 4. sensor -> Pi : ACK, ack number = 3,000,000,001                    (normal TCP: seq + 1)
 5. Pi           : 3,000,000,001 - 1 = 3,000,000,000                  (cookie back)
                   hash(secret, 172.29.2.42, 51000, 172.29.2.43, 1884, slot 7) = 3,000,000,000 again
                   same -> real client -> create the connection NOW, straight into the ACCEPT queue
 6. broker picks it up -> sensor is connected
```
- The SYN queue is never used for this connection, so "it is full" does not matter.
- Attacker: sends millions of SYNs -> the Pi answers each with a SYN-ACK and forgets it -> nothing fills up.
- A faked ACK doesn't work: without the secret key you can't make a number that matches the hash
  (the key stays inside the Pi kernel), and an old cookie expires after ~2 time slots.
- Only switched on when the SYN queue is full (`net.ipv4.tcp_syncookies=1`, set in `run_ids.sh`).
- Cost: a tiny hash per SYN; some TCP extras (options) are limited while cookies are used.
- Does NOT stop the bandwidth / CPU of the flood itself: that is what the IDS block (iptables) is for.

**Q: Why UDP port 5683? Can it be another one?**
5683 = **CoAP**, the standard UDP port for IoT devices, so the flood looks like an IoT UDP attack. Nothing listens
there on our Pi, the kernel just throws the packets away. **Any port works** (`-p` in hping3): detection uses
rate, sizes, protocol and flags. Avoid 53 (DNS), 22, 80, 443, 23: the model has "is it DNS / SSH / HTTP / Telnet"
features, so those ports change the features.

**Q: How many clients on one machine? Can one machine be publisher, subscriber AND broker?**
- Many: each client is just one TCP connection with its own **client ID**. Limits: RAM and ports (tens of thousands).
  Two clients with the SAME client ID: the broker kicks the older one (that happened on 7 Nov: two boards named node1).
- Yes, one machine can be all three: **the Pi is the broker AND a client** (the IDS connects to `127.0.0.1:1884`,
  publishes `ids/...` and subscribes `cmd/mitigation`). The dashboard is a publisher AND a subscriber.

**Current setup: all clients (our broker, port 1884)**
| Client (client ID) | Runs on | Publishes | Subscribes |
|---|---|---|---|
| node1, node2, node3 (`bot-node1..3`) | NodeMCUs | `sensors/node1..3` | nothing |
| TinyIDS (`tinyids`) | Pi | `ids/alerts`, `ids/stats`, `ids/status`, `ids/mitigation/status` | `cmd/mitigation` |
| Dashboard (`dashboard-laptop`) | laptop (Streamlit) | `cmd/mitigation` (only when a button is pressed) | `sensors/#`, `ids/#` |
| Brute force (`bf-1`, `bf-2`, ...) | laptop, attack 4 only | nothing (just tries to log in) | nothing |
= **5 permanent clients** (3 sensors + IDS + dashboard). Publishers: 3 sensors, IDS, dashboard. Subscribers: IDS, dashboard.
The bots' TCP flood is NOT an MQTT client (connect + close, no MQTT login). The bot commands don't use MQTT (UDP broadcast).

**All topics (8)**
| Topic | From -> to | What / how often |
|---|---|---|
| `sensors/node1`, `sensors/node2`, `sensors/node3` | NodeMCU -> dashboard | temperature + humidity, every 2 s |
| `ids/alerts` | IDS -> dashboard | one message per alert (attack, confidence, top-3 SHAP) |
| `ids/stats` | IDS -> dashboard | packets/s (total + per sender), windows, alerts, model ms, SHAP ms; every 1 s |
| `ids/status` | IDS -> dashboard | started at, models, gateway IP; once (retained) |
| `ids/mitigation/status` | IDS -> dashboard | IPS on/off + blocked / quarantined / rate-limited list, every 1 s (retained) |
| `cmd/mitigation` | dashboard -> IDS | buttons: IPS on/off, unblock, flush all |
(Removed 15 Nov: `cmd/bot` and `bot/<name>/status`.) Docker uses the same topics on port 1883.
The Pi also has the lab's own broker on 1883; we don't use it.

---

## 11. Streamlit, the bots, MQTT brute force, MQTT floods, Telnet (15 Nov)

**Q: Where does Streamlit run? Who subscribes to what?**
- On the **laptop**: `streamlit run laptop/dashboard.py -- <PI_IP>` starts a small web app; the browser opens
  `localhost:8501`.
- Inside it, the dashboard makes an **MQTT client** (`dashboard-laptop`) that connects to the **broker on the Pi**
  (port 1884, user `tinyids`) and subscribes to `sensors/#` and `ids/#`. Buttons publish to `cmd/mitigation`.
- The IDS on the Pi is another MQTT client that publishes the `ids/...` topics.
- Could it run on the Pi with the screen? Yes, but Streamlit + a browser use a lot of the Pi's RAM and CPU
  (slows the IDS and spoils the measurements). Laptop is better.

**Q: Did the bots crash the broker or the Pi?**
Neither. Each bot flooded the **Pi** (UDP -> 5683, TCP connect + close -> 1884); the IDS quarantined all 3 within
seconds. We did not measure whether the broker slowed down in those seconds.

**Q: Why didn't the bots try to break the MQTT password?**
Our firmware only has the 2 floods. Real Mirai does brute force: that is how it **recruits** new devices
(Telnet with default passwords). Could be added later.

**Q: What is MQTT brute force? Why do we log in at all?**
Guessing the broker's password (attack 4 in `launch.py`: tries common passwords one by one). If it works, the attacker can:
- **read** all sensor data,
- **inject fake readings** (e.g. temperature 90 C),
- publish to `cmd/mitigation` -> **flush the bans or turn the IPS off**.
The IDS catches it with a rule: 5 refused logins in 10 s -> BruteForce -> block.
Weak spot: sensors, dashboard and IDS share ONE password. Fix: separate users + an ACL (only the admin may publish
`cmd/mitigation`).

**Q: Is there an "MQTT flood"?**
Yes: CONNECT flood (thousands of logins), PUBLISH flood (huge message rate or giant messages), SUBSCRIBE flood /
subscribing to `#` to read everything. CICIoT2023 has (as far as I know) no MQTT-specific attack class; its attacks
are generic floods, Recon, Web, BruteForce, Spoofing, Mirai. The newer CICIoMT2024 dataset has MQTT attacks.
Our IDS would probably call a PUBLISH flood from one sender a "DoS flood" by its rate. **Not tested.**

**Q: What is Telnet?**
A **protocol** (TCP port 23, from 1969, standard 1983) and also the program that uses it. Name usually explained as
"**Tel**etype **Net**work" (no official full form). Remote text login like SSH, but **nothing encrypted**, not even
the password; SSH replaced it. Cheap IoT cameras / routers shipped with Telnet open and passwords like `admin/admin`.
Mirai scanned the internet for port 23, logged in with ~60 default passwords and took over hundreds of thousands of devices.

---

## 12. Who classifies, spoof tests, hping3, safety, run_ids.sh, port 1884, no_scipy (15 Nov)

**Q: rules.py doesn't use ML? Who classifies: the model or my engines?**
Correct, `rules.py` has **no ML**. TinyIDS = **two classifiers side by side** + one part that acts:
| Part | Classifies what | How |
|---|---|---|
| **ML model** (`detector.py`, LightGBM) | Attack or not, then which family (Flood, Recon, Spoofing, Web, BruteForce, Mirai) | Learned from CICIoT2023, on windows of 10 / 100 packets |
| **Rules** (`rules.py`, `address_watcher.py`) | Brute force (5 refused logins / 10 s), port scan (> 20 ports / 5 s), DoS vs DDoS (counts senders), ARP / fake-IP spoofing | Counting and if/else |
| **Response engine** (`response.py`) | **Classifies NOTHING.** Gets an alert from either side and picks the **action**: block 30 s / quarantine 120 s / rate-limit | Adds iptables rules |
Example: flood -> model says "Flood 0.97" -> rule counts 3 senders -> "DDoS" -> response engine quarantines all 3.
Name for this: **hybrid IDS**. Viva line: "ML for patterns with no simple rule (floods, scans); rules for things that are
literally countable (5 wrong passwords). A rule never guesses."

**Q: When did we test fake source IPs?**
**Only in Docker (13 Nov evening, at home), never on the real Pi.** `spoofed_flood syn` / `udp` -> caught by
`address_watcher.py` (one MAC, many IPs -> MAC blocked). ARP spoofing: also only Docker.
Lab results say so (`docs/results/2026-11-13_pi_lab_v4/RESULTS.md`: "spoofing on the Pi" not done).

**Q: Why don't we use hping3 directly?**
hping3 is a **Linux** tool; it doesn't run on Windows (the laptop). scapy works on Windows through Npcap, so the laptop
uses scapy (`launch.py`). **Docker does use hping3 and nmap** (the attacker container is Linux).
For hping3 on the real laptop: WSL (Ubuntu inside Windows).

**Q: Where is safety.py?**
**There is no such file.** "Safety" is a feature, spread over 2 files:
- `pi/tinyids/response.py`: never-block list (router, the Pi itself), `keep_admin_open` (admin SSH + dashboard always
  allowed), `release_all` (removes every rule).
- `pi/run_tinyids.py`: capture filter skips the admin's SSH; `release_all` runs on Ctrl+C.

**Q: What is run_ids.sh's job?**
8 lines, 4 things, so I type ONE command instead of four:
1. turns on **SYN cookies**,
2. starts **our broker** (Mosquitto with `broker/tinyids_broker.conf`, port 1884) in the background,
3. starts **`run_tinyids.py`** with `sudo`, `wlan0`, port 1884 + my options (`admin <ip>` ...),
4. on Ctrl+C, **stops our broker** too.

**Q: Why port 1884 and not 1883? What is on 1883?**
- 1883 = the standard MQTT port. On the lab Pi a **Mosquitto service was already running on 1883** (installing
  Mosquitto with apt starts it as a system service with default settings).
- We didn't want to reconfigure / break what was there, so **ours runs separately on 1884** with its own settings and
  password, started / stopped by `run_ids.sh`.
- Docker uses 1883 (empty container, nothing else there).

**Q: What is no_scipy.py? Just don't import scipy!**
**We never import scipy. LightGBM does**, inside the installed library (not our repo):
`site-packages/lightgbm/basic.py`, line 30: `import scipy.sparse`
(laptop: `C:\Users\HOME\AppData\Local\Programs\Python\Python312\Lib\site-packages\lightgbm\basic.py`,
Pi: `~/tinyids/venv/lib/python3.*/site-packages/lightgbm/basic.py`).
That loads ~27 MB of RAM every time we `import lightgbm`, for something we never use.
Why not just remove it:
- comment out line 30 inside LightGBM -> lines 97-123 of the same file use `scipy.sparse` while loading -> **crash**;
  and every `pip install` overwrites the edit.
- uninstall scipy from the Pi -> `import lightgbm` fails ("No module named scipy").
So `no_scipy.py` (25 lines) puts a **fake empty scipy** into Python's memory BEFORE LightGBM loads. LightGBM gets the
fake; its only use of scipy is "is this input a sparse matrix?" and the fake always says "no".
Predictions identical (checked on 200 rows). Delete it = +27 MB = back over the 100 MB target.
Viva line: "LightGBM imports scipy even though we never use it; a 25-line stand-in saves 27 MB."

---

## 13. My story of the whole system (checked) + plan: attacks with hping3 / nmap from WSL (15 Nov)

**My story, checked:**
- NodeMCUs: sensor (publishes `sensors/nodeX` to the broker on the Pi) + hidden bot part ("malware", simulated).
  A UDP broadcast from the laptop -> they become bots -> UDP or TCP flood at the Pi (I choose). OK.
  BUT: the boards still have the OLD firmware (`cmd/bot` over MQTT). New broadcast firmware = re-flash all 3 first.
- Dashboard: ONE file `laptop/dashboard.py`, started with `streamlit run`; inside it ONE MQTT client that subscribes
  `sensors/#` + `ids/#` and publishes `cmd/mitigation` (Flush / IPS on-off buttons); browser at `localhost:8501`. OK.
- Pi: scapy capture on `wlan0` -> kernel BPF filter -> windows -> model judges. OK.
  - WRONG: SHAP is NOT before the model. It runs ONLY AFTER the model says "attack", to explain that alert.
  - WRONG: no alert goes out before the model. What goes out every second regardless = `ids/stats` (packet counts,
    model speed), statistics, not alerts. `ids/alerts` only AFTER a decision: model -> SHAP -> alert, OR a rule
    (brute force / port scan / spoofing), which skips the model.
  - WRONG: there is no separate "alert client service". It is ONE MQTT client INSIDE the IDS program
    (`publisher.py`, client ID `tinyids`): publishes alerts / stats / status, listens to `cmd/mitigation`.
  - Laptop dashboard subscribed -> shows them. OK.
  - Sensor temperature data goes NodeMCU -> broker -> dashboard directly, NOT through the model
    (the IDS only watches a copy of those packets).

**Plan: attacks with hping3 + nmap from WSL (instead of scapy)**
Good because: exactly what the proposal says ("hping3, nmap"), no scapy to explain, and I can type the real commands
myself to show off.
1. WSL networking is the risk. Default WSL2 = behind a NAT inside Windows. Use **"mirrored" networking**
   (`.wslconfig`, Windows 11): WSL then uses the laptop's real IP and Wi-Fi. Even mirrored, **fake source IPs
   (`--rand-source`)** and **ARP spoofing** may be blocked by Windows. Normal SYN / UDP floods + nmap should work.
   **Test once first.**
2. What runs where:
| Attack | Tool | Where |
|---|---|---|
| SYN flood, UDP flood | hping3 | WSL |
| Spoofed flood | hping3 `--rand-source` | WSL (maybe blocked, test) |
| Port scan | nmap | WSL (nmap also exists for Windows) |
| MQTT brute force | Python (paho) or a `mosquitto_pub` loop | WSL or PowerShell (hping3 / nmap can't do MQTT logins) |
| ARP spoofing | needs scapy or `arpspoof` | probably NOT from WSL -> drop from menu (still in Docker) |
| Bots | `bot.py` (UDP broadcast) | PowerShell safest; WSL only if mirrored mode passes broadcasts |
3. New `launch.py`: no scapy, runs INSIDE WSL, menu calls hping3 / nmap and **prints the exact command before
   running it** (e.g. `sudo hping3 -S -p 1884 -i u1000 172.29.2.43`), so I learn the commands and can type them myself.
   Options 1 SYN, 2 UDP, 3 scan, 4 brute force, 5-6 spoofed, 7 dropped / Docker only, 8 bot, 9 all.
   Use `-i u1000` (1,000 packets/s), NOT `--flood` (could knock the Pi off the Wi-Fi again). `bot.py` stays.
4. WSL: `wsl -l -v` lists the distros, `*` = default (what plain `wsl` opens). `wsl -d Ubuntu-24.04` = a specific one.
   Use 24.04.
5. First a 5-minute test: mirrored mode on -> install hping3 + nmap in Ubuntu 24.04 -> 5 SYNs at a target -> check they
   leave from the laptop's real IP.

---

## 14. Which IPs are hard-coded, and what I type in the lab (16 Nov)

**My question:** how many scripts in `laptop/` and `pi/` have an IP written inside them, and what do I have to type
every time I connect (NodeMCU IPs, Pi IP)?

**Answer:** only ONE file has an IP written into the code: the NodeMCU firmware. Everything else either gets the IP
when I start it, or finds it by itself. (IPs in comments / docstrings are only usage examples.)

**Hard-coded (fixed until I change the file and re-flash)**

| File | What is in it | When I must change it |
|---|---|---|
| `laptop/nodemcu_bot/nodemcu_bot.ino` | `GATEWAY_IP = "172.29.2.43"` (the Pi), `WIFI_SSID = "IIITA"` + its password, `NODE_NAME` (node1/2/3, one per board) | **If the Pi's IP changes, re-flash all 3 NodeMCUs.** Otherwise they publish to an old IP and the bots attack the wrong address. |
| `pi/setup_pi.sh` | college proxy `172.31.2.3:8080` | Only for the one-time setup, and only off the college Wi-Fi |

**Typed every time I run it (the IP can change, so I give it)**

| What I run | What I type |
|---|---|
| Pi detector | `./run_ids.sh admin <LAPTOP_IP>` |
| Dashboard (laptop) | `streamlit run laptop/dashboard.py -- <PI_IP>` |
| Attacks (WSL) | `python3 launch.py <PI_IP>` |
| Copying code to the Pi | `scp ... pi@<PI_IP>:~/tinyids/` |

**Found automatically (nothing to type)**
- **Detector on the Pi:** its own IP, the router's IP and MAC, and which IP belongs to which NodeMCU (it learns them
  from their MQTT messages on `sensors/<name>`).
- **`bot.py`:** needs no IP at all. It broadcasts to every device on the Wi-Fi, and the bots already have the Pi's IP
  from their firmware.
- **The MQTT login `tinyids` / `tinyids123`:** the same everywhere, set in the code.

**Lab checklist, in order**
1. On the Pi, run `hostname -I` to get **PI_IP**.
2. In PowerShell on the laptop, run `ipconfig` to get **LAPTOP_IP**.
3. **If PI_IP is not 172.29.2.43**, change `GATEWAY_IP` in the `.ino` and re-flash all 3 NodeMCUs. (They need
   re-flashing anyway: they still have the old firmware without the UDP-broadcast bot command.)
4. Then use PI_IP for the dashboard and `launch.py`, and LAPTOP_IP for `run_ids.sh admin`.

---

## 15. SHAP, top-3 vs top-20, the SSH false alarm, calibration vs retraining (16 Nov)

**My questions:** What is SHAP and why do we use it? Is it the standard? Why can't the model just tell us its top
features, and we send them over MQTT? Which file is it in? Can we show top 20 instead of 3? When do we calibrate on our
own data, do we need it, and how does it help when the model is already trained? Did we implement the "learn normal
traffic" button?

### 1. What SHAP is and why we use it

SHAP is a method that says, **for one particular alert**, how much each feature pushed the model towards "attack".
Example: `syn_flag_number +2.1, Rate +1.4, Tot size +0.6`. Those are the "top 3 reasons" in every alert.

**Why not just ask the model for its top features?** LightGBM has a built-in "feature importance", but that is **one
global list for the whole model**: the same top 3 for every alert, whatever happened. SHAP is **per alert**: a SYN
flood alert and a UDP flood alert get different reasons, because each explains *that* window. That is what "explain why
an alert fired" means in the proposal.

**Is it the standard?** Yes. The most widely used explanation method, and the proposal asks for it by name (objective 5,
RQ3 "SHAP under 50 ms", reference 6 = Lundberg 2017). For tree models there is **TreeSHAP**, which is exact and fast.
LightGBM has it built in, so we don't even install the `shap` library: `predict(..., pred_contrib=True)`.

**"Use some function and send it over MQTT"** is exactly what we already do: the function computes SHAP, and the
result goes to the dashboard on topic `ids/alerts`.

**Which file:** `pi/tinyids/detector.py`, function `explain()`. The "3" is the `[:3]` in
`top = np.argsort(-np.abs(mine))[:3]`.

**Top 20?** Yes, anything from 1 to 30 (the model has **30 features**), by changing that `3`. SHAP computes all 30
values anyway, so the time is almost the same. We keep 3 because the proposal says "top three features", and an alert
with 20 reasons is unreadable.

### 2. The SSH false alarm: what is implemented and what is not

- **Way 1, ignore the admin's SSH: implemented.** Started with `admin <LAPTOP_IP>`, `capture_filter()` in
  `pi/run_tinyids.py` skips my laptop's SSH packets (port 22) and its already-open dashboard connection. The detector
  never sees them.
- **Way 2, a "learn normal traffic" button: NOT implemented.** No such code in the dashboard or on the Pi. The only
  trace is a note in `windows.py`: "Fix planned: retrain with benign windows recorded from our own testbed."

### 3. "The model is already trained, so how does learning live traffic help?"

The cause of the false alarms: the model was trained on **CICIoT2023's** normal traffic (their devices, their lab). Our
NodeMCUs, SSH and reconnects look different from anything in that data. The model has **never seen our normal
traffic**, so it guesses. The proposal itself warns about this in its "validity note".

"Already trained" does not mean frozen forever. Two ways to fix it:

**A. Calibration: change the decision threshold, not the model** (cheap)
- Record a few minutes of our normal traffic with no attacks. Look at the "attack probability" the model gives each
  window.
- Example: normal traffic never scores above 0.65. Then set `attack_threshold` in `settings.py` just above that
  (today it is 0.70).
- The model is untouched. We only move the line where we say "attack".

**B. Retraining: actually teach the model** (better; my friend's part)
- Save our recorded normal windows labelled "Benign" and add them to the CICIoT2023 training data.
- Retrain and copy the new `binary.txt` / `family.txt` to the Pi. Now the model has seen our traffic and stops
  flagging it.
- LightGBM can also continue training an existing model with a few extra trees instead of starting from zero.

The "button" idea is just a way to do the **recording** part live. Training stays offline.

**Do we need it?** Not urgently. The false alarms are low-confidence (0.3–0.7), and `alert_filter.py` already blocks
most of them (an unsure detection must repeat before it alerts). Worth doing if there is time: a good point for the
report.

**Danger to mention in the viva:** if an attack happens while recording, the model learns that attack as "normal"
(this is called **poisoning**). So record only when the network is known to be clean.

**False flood alarms:** same fix. Any normal traffic flagged by mistake disappears once the model has seen it, or once
the threshold sits above it.

---

## 16. IAT (the "clock" feature), DoS vs DDoS, SYN flood vs TCP flood (16 Nov)

**My questions:** How does IAT work? Training said IAT was ~99% of the importance, so how could it tell brute force from
SYN flood from UDP flood from port scan? Why did we remove it? How do we tell DoS from DDoS, isn't it just counting? Is
"SYN flood" the same as "TCP flood"? What would change if we wanted to use IAT?

### 1. IAT: what it should be vs what it is in CICIoT2023

**What IAT should be:** Inter-Arrival Time = the time gap between 2 packets. That is the textbook meaning and what the
column name promises (a flood has tiny gaps, a sensor about 2 s).

**What the CICIoT2023 IAT column actually behaves like:** not small gaps like 0.001 s, but numbers that follow **when the
packet was captured**, like a clock reading (a quirk of how the authors' tool computed it; other papers on this dataset
report the same problem).

**The clock example (how I remember it):** the authors recorded each attack in its own time slot.
- SYN flood recorded from 10:00 to 11:00 -> its IAT values sit in one range.
- UDP flood recorded from 11:00 to 12:00 -> its IAT values sit in another range.
- Brute force, port scan, ... each in their own slot -> each its own range.
- The model learns: "IAT in range A = SYN flood, range B = UDP flood". It does not look at the attack at all.

The model doesn't literally see "10 am"; it sees a number that **acts like a clock**, and since every attack had its own
time slot, that number alone almost gives away the answer. That is why IAT looked like ~99% of the importance. Like a
student who memorized "question 7 is always B" without understanding the question.

Technical name: **data leakage** / **shortcut feature** (the answer leaks into the input through the way the data was
recorded).

**Why it is useless live:** on the Pi, a SYN flood at 3 pm gives a "time" the model has never seen -> nonsense.

**Measured effect** (from `START.md`):

| | With IAT | Without IAT |
|---|---|---|
| Binary (attack or normal) | ~99.4% | ~99.4% (no change) |
| 8-class (which attack) | ~99.5% | ~91% |

Binary doesn't care: flags, sizes and rate are enough to say "attack". Only "which family" drops, because the shortcut
is gone.

### 2. DoS vs DDoS = counting

Seen from **one** sender, DoS and DDoS look exactly the same (same SYN packets, same sizes, same rate). The only
difference is **how many machines attack at once**, which is not a property of one window, so no per-window feature
can see it (IAT neither; with IAT the model separated them only because DoS and DDoS were recorded at different times).

So: the model says only **"Flood"**, and `FloodCounter` in `pi/tinyids/rules.py` counts the senders: 3 or more senders
flooding within 10 s = **DDoS**, one sender = **DoS**. That is how the 3 bots got "DDoS (3 senders)" in the lab.

### 3. SYN flood vs TCP flood

Both use TCP, but they are different attacks (CICIoT2023 has separate classes for them):
- **SYN flood:** only the first packet of a connection (SYN), again and again; the handshake is never finished. The Pi
  keeps a half-open slot for each until its table is full. This is `hping3 -S`. SYN cookies on the Pi defend against it.
- **TCP flood (connection flood):** complete connections opened and closed very fast (SYN, SYN-ACK, ACK, then FIN).
  This is what our **NodeMCU bots** do in `tcp` mode.
- The dataset also has PSH+ACK floods and RST/FIN floods; they differ only in the **flags** they set.

The model separates them by the **flag features** (`syn_flag_number`, `ack_flag_number`, `fin_flag_number`, ...). Our
model groups all of them as "Flood" anyway.

### 4. What if we wanted to use IAT?

Small code change:
1. `pi/tinyids/features.py`: compute IAT = average gap between the packet times in the window (~2 lines; the times are
   already stored).
2. `model/make_ids_models.py`: add `IAT` to `LIVE_FEATURES`, retrain -> new `binary.txt`, `family.txt`, `meta.json`.
3. Nothing else: `detector.py` and the pipeline read the feature list from `meta.json` automatically.

**But it would break the live detector:** our live IAT would be a REAL time gap, while the model learned the dataset's
"clock" IAT, on a completely different scale. Test score great (99.5%), live input nonsense.

We already have an honest timing feature: **`Rate`** (packets per second of the connection), computed live in
`features.py`.

**Viva answer:** "IAT in CICIoT2023 encodes when each attack was recorded, not how it behaves. With it 8-class is 99.5%,
but it is a shortcut the gateway can't reproduce live. Without it we get 91%, honestly. DoS vs DDoS is decided by
counting senders, which is the real definition."

---

## 17. Why "Recon" / "Web" on the bots, why rules, what is in the dataset (16 Nov, checked on the data)

**My questions:** Why do the bots get labelled "Recon" (and "Web") around a flood, like in every lab run? Why did the
bot UDP flood look like "Web" / "Recon"? Why do we need rules for DDoS, spoofing and brute force at all: shouldn't the
dataset have features for them (many source IPs -> one destination = DDoS)? Is the data bad? Did we use validation.csv?

### 1. Docker test 16 Nov: what really happened with the bot UDP flood
- The **100-packet windows** of the bot UDP flood were classified correctly: `DoS flood`, then `DDoS flood (3 senders)`
  (top-3 reasons: `Rate` ~13,000-36,000/s, `Protocol Type` 16.6 = UDP, short `flow_duration`).
- The wrong labels (`Web` 0.94, `Recon` 0.60, `Spoofing`) came only from the **10-packet windows** of the same traffic.
- So the flood IS detected; the extra wrong alerts come from the small windows.

### 2. Why the small windows of a flood get "Recon" / "Web"
- Every sender is cut into two windows at the same time: 10 packets and 100 packets (as in CICIoT2023).
- In the dataset, **Flood rows were always made from 100-packet windows**. The model has **never seen a 10-packet
  piece of a flood**. On a 10-packet window, Flood is not allowed (we throw away a family that comes from the wrong
  window size), so if the model's answer is something else, it picks the closest 10-packet family: Recon or Web.
- Two things make those small windows look like Recon/Web (checked: dataset medians from `validation.csv`):
  - **At the start of a flood the connection counters are still small.** `Header_Length` (bytes of headers in the
    connection so far) is ~16,000-25,000 in the dataset's UDP flood rows, but only ~2,000-3,600 in Recon rows. Our first
    windows of a new flood have small counters, so they look like Recon.
  - **At the start and end of a flood, normal sensor packets (MQTT over TCP) and flood packets (UDP) mix in one
    window.** `Protocol Type` 12.6 in the "Web" alert = a mix of 6 (TCP) and 17 (UDP). No dataset class looks like that
    mix, and Web rows happen to sit in between (8.2-8.7).
- That is also why "Recon" on the bots **after a TCP flood** showed up in every lab run: it is the flood's start / end
  windows, not a real scan.
- Low confidence (0.5-0.8) -> only rate-limited, not blocked. The real Flood alert (0.97+) quarantines the bot anyway.
- Possible fix (not done): while a sender is flagged as Flood, ignore its 10-packet alerts (the same trick the port scan
  rule already uses: while a sender scans, the model's "Flood" for it is ignored).

**Recon on 172.30.0.30 in Docker** = the dashboard container. In Docker the IDS runs without `admin <ip>`, so the
dashboard's MQTT connection is inspected and looks like Recon. On the Pi, `admin <LAPTOP_IP>` skips it.

### 3. Why rules? Because the dataset has NO addresses (checked)
The CICIoT2023 columns (header of `train.csv`): `flow_duration, Header_Length, Protocol Type, ..., Tot size, IAT, Number,
..., label`. **There is no source IP, no destination IP, no MAC.** Every row is the average of a window of packets.

- **DDoS:** the model can't count senders, because a row doesn't know who sent it. And the rows look the same: median of
  `DDoS-UDP_Flood` vs `DoS-UDP_Flood`: Protocol 17 vs 17, size 50.0 vs 50.2, rate ~7,500 vs ~10,500/s. Almost identical.
  -> counting senders (`FloodCounter`) is the ONLY way, and it is the definition of DDoS anyway.
- **Spoofing:** `MITM-ArpSpoofing` rows: median ARP = 0, TCP = 1, size 544. The rows are mostly the normal traffic the
  attacker forwarded, not the fake ARP messages themselves. With no MAC column, "one MAC uses many IPs" can't be learned.
  -> `AddressWatcher` rule.
- **Brute force:** `DictionaryBruteForce` = only **290 rows** in validation (vs 136,466 for DDoS-UDP_Flood), and they
  are not MQTT logins. Our attack is MQTT: the broker's "login refused" answer is 100% clear proof. -> `BruteForceRule`.
- **Port scan:** Recon rows look a lot like a fast SYN flood from one sender; the difference (MANY ports vs ONE port)
  needs the port number, which is not a feature. -> `PortScanRule`.

**Is the data bad?** Not bad, but made for a different job: it describes the *shape* of traffic in a window, not *who*
talks to *whom*. The model answers "does this traffic look like an attack, and what kind"; the rules answer the "who /
how many" questions. That split is a design decision I can defend.

**Bonus (IAT, section 16) visible in the same table:** IAT median ~83,000,000 for every flood, ~166,000,000 for Recon /
Web / DNS spoofing, ~0.05-0.09 for Benign / brute force / ARP spoofing. Clusters per recording, not packet gaps.

### 4. Did we use validation.csv?
**Yes.** `model/make_ids_models.py` and `make_small_models.py` train on 20% of `train.csv`, use 20% of
`validation.csv` for **early stopping** (stop adding trees when validation stops improving) and to **choose the small
model's size**, and report the final score on `test.csv`. Train = learn, validation = tune, test = final honest score.

### Viva answer
"The dataset rows have no IP or MAC addresses, so the model can only judge the shape of the traffic. DDoS (how many
senders), spoofing (does the MAC fit the IP), port scans (how many ports) and MQTT brute force (refused logins) need
addresses, ports or protocol answers, so we check those with simple, explainable rules next to the model. The Recon
labels on the bots are the start and end windows of a flood: a 10-packet slice of a flood, which the dataset never
contains."

---

## 18. ONNX, Treelite, lleaves + how to read the SHAP charts (16 Nov)

**My questions:** What are ONNX, Treelite and lleaves? Which did we use, and why not the others? Do I need hard maths?
Would Treelite / lleaves make the model and SHAP faster, use less RAM, make the model smaller? How do I read the SHAP
bar charts (what is the x axis, why negative, why not 0 to 1)?

### 1. The three tools (no maths needed: they store or run a model, they are not new maths)
A tree model = a big flowchart of if/else questions ("is syn_flag_number > 0.5? then is Rate > 40? ...").

| Tool | What it is | Do we use it? |
|---|---|---|
| **ONNX** | A standard **file format** for models (like PDF for documents) + **onnxruntime** to run it. Can shrink a model to **INT8** (whole numbers instead of decimals). | **Yes, only for the RQ2 comparison:** `model/compress.py` makes the `.onnx` files (MLP, CNN, RF, pruned LightGBM, some INT8), `pi/benchmark/rq2_benchmark.py` runs them on the Pi. The proposal asks for "ONNX with INT8 quantization". |
| **Treelite** | Turns the tree flowchart into **C code** and compiles it into a fast program. | **No.** Not anywhere in the project. |
| **lleaves** | Same idea, made for LightGBM, uses the LLVM compiler. | **No.** Not anywhere in the project. |

The live detector uses LightGBM's own `.txt` files (`pi/models/binary.txt`, `family.txt`).

### 2. Would Treelite / lleaves be better for us? No.
| Question | Answer |
|---|---|
| Faster prediction? | **Yes**, compiled if/else code is faster. But we already measured ~1.1 ms per window on the Pi; the target is < 5 ms. We don't need it. |
| Faster SHAP? | **No.** They can only predict, they can't explain. SHAP would still need LightGBM (`pred_contrib=True`). |
| Less RAM? | **No, more.** Because of SHAP we must keep LightGBM loaded anyway, so it would be LightGBM + the compiled model. lleaves also needs the LLVM library (big). |
| Smaller model? | **No, usually bigger.** The compiled file holds machine code for every node; our `.txt` models are already < 1 MB (the target). |
| Better overall? | **No.** More installs on the Pi, more to explain, no SHAP, and we already meet every target. Good "future work" sentence: "if prediction speed ever becomes the bottleneck, compile the trees with Treelite / lleaves". |

### 3. How to read the SHAP bar chart on the dashboard
- **Y axis:** the 3 features and their value in that window (e.g. `AVG = 56.4` = average packet size 56.4 bytes).
- **X axis:** the **SHAP value** = how much that feature pushed the model **towards** (+, bar to the right) or **away
  from** (-, bar to the left) the attack it named.
- **Why not 0 to 1:** 0-to-1 is *feature importance* (one global list). SHAP values are in the model's internal score
  units (log-odds) and can be any size, + or -. They add up:
  `starting score + SHAP of all 30 features = final score -> (softmax) -> confidence 0.99`. Only that last step gives 0-1.
- **Why the 13 Nov screenshots showed negative bars:** the code picked the 3 biggest values **either way** (by size,
  ignoring the sign). For the floods, the 3 biggest happened to push AGAINST Flood (the other 27 features pushed for it
  more). **Fixed on 16 Nov:** `detector.py` now picks the 3 biggest pushes TOWARDS the attack
  (`np.argsort(-mine)[:3]`). Checked in Docker: 40 alerts, 0 negative bars.
- Viva line: "Each bar is that feature's SHAP contribution to the predicted attack. We show the three largest positive
  contributions, i.e. the features that pushed the model most towards its verdict."

---

## 19. Is there a better dataset? CICIoMT2024, Mendeley, datasets with IPs (16 Nov)

**My question:** Isn't there a better dataset, e.g. CICIoMT2024, with source / destination IPs and MACs, so the model can
learn DDoS and spoofing itself? Is the Mendeley processed data better?

**1. Mendeley "Derived CICIoT2023 datasets" (proposal reference 5):** NOT better, just smaller. It is the same
CICIoT2023 rows, pre-sampled / balanced for easier training. Same 46 features, same missing IPs, same IAT problem.

**2. CICIoMT2024 (CIC, Internet of *Medical* Things):** same lab, same style of window features as CICIoT2023 (as far
as I know also without IP columns in the CSVs). Its plus: it has **MQTT attacks** (MQTT connect / publish floods,
malformed data), which fit our broker. But it is a different project (medical devices) and not what the proposal names.

**3. Datasets that DO have IP columns:** e.g. Edge-IIoTset, TON_IoT, Bot-IoT, MQTT-IoT-IDS2020. Also CICIoT2023 itself
publishes the raw **PCAP** files (all packets with IPs and MACs); only the CSVs dropped them.

**4. Would IPs in the training data help? No, they would hurt.** The model would memorize "IP 192.168.x.y = attacker"
from THEIR lab. On our network the addresses are different, so it learns nothing useful. That is why researchers delete
IP columns before training (another shortcut, like IAT).
- To learn DDoS you need a feature like "how many different senders hit the Pi in the last 10 s". That is exactly what
  `FloodCounter` already counts. Putting it in the model would only learn the threshold we set by hand (3 senders).
- Same for spoofing: "how many IPs per MAC" = what `AddressWatcher` counts.

**5. Should we switch? No.**
- The proposal names CICIoT2023; switching = retrain all 4 models, redo RQ1/RQ2, change the live extractor.
- The real fix for our false alarms is **our own recorded traffic** (section 15), not another lab's dataset.
- Good for the paper: "future work: MQTT-specific attacks from CICIoMT2024 / Edge-IIoTset".

**Viva answer:** "Address columns don't generalize: a model that learns IPs memorizes the dataset's lab. The useful
information is counts (senders per target, IPs per MAC, ports per sender), which we compute live with explainable rules.
CICIoT2023 was given in the proposal; CICIoMT2024 and Edge-IIoTset are future work for MQTT-specific attacks."

---

## 20. Why the NodeMCU MQTT traffic is NOT flagged but SSH was, and why "Recon" (16 Nov)

**My question:** The model never saw MQTT traffic in the dataset, so why doesn't it flag our NodeMCUs, while it DID flag
my SSH traffic (the reason we added the SSH filter)? Are we even checking the MQTT traffic with the model? And why is a
port scan called "Recon", not "port scan"?

### 1. The model (almost) never looks at the NodeMCUs' normal traffic
- The model only classifies a sender when it has a **full window: 10 packets within 5 seconds** (`settings.py`:
  `small_window 10`, `window_timeout 5.0`).
- A NodeMCU publishes **one reading every 2 seconds** (`nodemcu_bot.ino`: `millis() - lastReading >= 2000`). That is
  about 2-3 packets in 5 s. The window never fills, so `windows.py` throws it away (`drop_old`).
- So the sensors' normal traffic is **never shown to the model at all**. Not "benign": simply not judged.
  `windows.py` says it openly: "KNOWN LIMITATION: senders slower than ~2 packets/s are never classified by the model".

### 2. Why SSH was flagged
- An SSH session sends MANY packets fast (every key press, every line of output, the ACKs). 10 packets fill in well
  under a second, so the model DOES classify it.
- The model has never seen SSH sessions like mine, so it guessed "attack" -> false alarm.
- Fix: `admin <LAPTOP_IP>` -> `capture_filter()` skips my SSH (port 22). Port 22 from everyone else is still checked.

### 3. When the NodeMCUs DO get false alarms
- At **boot / Wi-Fi reconnect** a NodeMCU sends a short burst (ARP, TCP handshake, MQTT login, first readings). That
  can fill a 10-packet window in 5 s -> classified -> sometimes a low-confidence false alarm (0.3-0.7, seen in the lab).
- And during floods (section 17): the start/end windows give "Recon" / "Web".

### 4. Is MQTT checked at all? Yes, but mostly by rules, not the model
| What | Checked by |
|---|---|
| Sensor's normal readings (slow) | NOT the model (window never fills). `SensorRegistry` learns "this IP = node1". |
| Any fast sender (floods, scans, SSH, bursts) | the model |
| MQTT logins | `BruteForceRule` (refused logins counted) |
| Many ports | `PortScanRule` |
| IP / MAC mismatch | `AddressWatcher` |

**Honest limitation for the viva:** a slow attack (fewer than 10 packets per 5 s, e.g. a slow scan or a few malicious
MQTT messages) is not seen by the model. The rules still catch slow brute force. Fix for later: record our own normal
traffic and train with smaller windows.

### 5. Why "Recon" and not "port scan"
- **Recon** (reconnaissance = "looking around before attacking") is the dataset's **family name**. It covers 5 attacks:
  PortScan, OSScan, HostDiscovery, PingSweep, VulnerabilityScan. The model only says the family.
- Our `PortScanRule` knows it is a port scan (many ports from one sender), but it reports it with the family name
  "Recon" so the dashboard groups it with the model's Recon alerts. Its reasons say it: "different ports: 1024".
- It could be renamed to "Recon (port scan)" for the rule alerts: a one-word change in `run_tinyids.py` (not done).

**Viva answer:** "The model only judges senders that fill a 10-packet window within 5 seconds. Our sensors send one
reading every 2 seconds, so their normal traffic is never classified; that's why they weren't flagged but my SSH
session, which is fast, was. MQTT is protected by rules: refused logins for brute force, sensor IP learning, and the
port and address rules."

---

## Next (continue later)

Go through it one piece at a time: Claude explains a piece, then quizzes me like the professor would.
Start with the response engine (block / quarantine / rate-limit), the core of my part.
