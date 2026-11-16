# The dataset, the features and the model: why we do it this way (16 Nov 2026)

> ## ⭐ WHAT OUR SYSTEM DETECTS, WITH WHICH TOOL, AND WHO CATCHES IT
>
> | Family | Dataset attacks | Tool to generate it | Caught by |
> |---|---|---|---|
> | **Flood (DoS / DDoS)** | SYN, UDP, ICMP, TCP, PSH-ACK, RST-FIN floods + the fragmentation floods | **all hping3**: `-S`, `--udp`, `--icmp`, `-A`, `-PA`, `-RF`, `-f` | **model**. These differ only in flags and protocol, which we compute exactly like the dataset authors, so the model could even name the type (SYN / UDP / ICMP …). DoS vs DDoS = counting senders (rule). |
> | **Recon** | port scan, OS scan, vulnerability scan (ping sweep + host discovery dropped: < 10 packets, never a full window) | **all nmap**: `-sT` / `-sS`, `-O`, `--script vuln` | **model** + the port-scan rule |
> | **Brute force** | dictionary brute force | `mosquitto_pub` (ours, MQTT logins) | **rule**. The dataset has only 290 rows of it (validation), and they are not MQTT. |
> | **Spoofing** | ARP spoofing, DNS spoofing | `arpspoof` (not hping3 / nmap) | **rule**. The dataset rows don't contain the fake ARP messages. |
> | **Benign** | — | the NodeMCUs (normal MQTT readings) | **model** (with our own recorded rows) |
>
> **hping3 + nmap cover Flood and Recon completely.** The only floods we skip are HTTP flood and SlowLoris (they need
> a web server, the Pi has none). Brute force and spoofing need their own small tools, but rules catch those anyway.
>
> **The model does 3 jobs: Benign / Flood / Recon** (maybe naming the flood type). **The rules do** brute force,
> spoofing, DoS-vs-DDoS and the port-scan confirmation. No new rules are planned.
>
> *Status: this is the PLAN. Not trained or tested yet (see section 12).*

---

## 1. Is the CSV raw data? No: it is computed

**Q: The dataset is just CSV files. Isn't that raw data? Who computed anything?**

No. There are two things:
- **Raw = the `.pcap` files.** For each packet: the time it arrived and its bytes (IPs, ports, flags, payload).
- **The CSV = computed from the pcaps** by the authors' Python script (`pcap2csv`, built on the DPKT library; we
  downloaded it into `dataset/cic_code/`). The script cuts the packets into groups and writes **one row per group**.

You can see it in the numbers: none of them can be a single packet's field.

| Column | Example value | Why it is computed |
|---|---|---|
| `syn_flag_number` | 0.3 | A packet's SYN flag is 0 or 1. 0.3 = "30% of the packets in the group had SYN": an average. |
| `Tot size` | 50.0 | The average packet size in the group. |
| `Rate` | 8,048 | A packet has no "rate". Packets per second over the group's time span. |
| `Header_Length` | 22,825 | No header is 22,825 bytes (a UDP header is 8). Something added up. |

**On the Pi we do the same job live:** `pi/tinyids/features.py` turns the captured packets into the same columns. When
I said "extractor" I meant exactly this: **the code that turns packets into the numbers**. Theirs made the training
data, ours makes the live data. Where the two formulas differ, the same traffic gives different numbers.

---

## 2. What their code really does (read in `dataset/cic_code/pcap2csv/Feature_extraction.py` + `README.pdf`)

**Q: Where is their feature code, and what does it do?**

From the CIC download page, folder "Supplementary Materials" -> `pcap2csv.zip`. What it does, in plain words:

1. **A row = the next 10 packets in the capture file, whoever sent them.** (We group per sender: 10 packets from the
   same IP. In a flood recording almost all packets are the attacker's, so the result is similar.)
2. For those packets it computes:

| Feature | Their formula (code + README) | Ours (`features.py`) | Same? |
|---|---|---|---|
| Flags (`syn_flag_number` …) | 0/1 per packet, averaged | same | ✅ |
| `Tot size`, `Min`, `Max`, `AVG`, `Std` | frame size per packet; avg / min / max / std of the group | same | ✅ |
| `TCP`, `UDP`, `ICMP`, `HTTP`, `SSH`, … | 0/1 per packet, averaged | same | ✅ |
| `Protocol Type` | **the most common** protocol in the group ("mode") | **the average** | ❌ e.g. 4 TCP (6) + 6 UDP (17) packets: theirs = 17, ours = 12.6 (that is the weird `12.6` in our "Web" alert) |
| `Rate` | packets in the group ÷ (time of last − time of first) = **plain packets per second** | per connection -> 0 for hping3 (new port every packet) | ❌ |
| `LLC` | **a bug in their code**: `type(self.packet == dpkt.llc)` is always "true" -> **LLC = 1 for every packet** | 0 | ❌ useless feature |
| `Header_Length` | README: "mean header length of the transport layer" (UDP 8, TCP ~20) | sum over the connection | ❌ and **their own CSV doesn't follow their README** (UDP floods ~22,825) |
| `IAT` | README: "interval between current and previous packet" | not used | ❌ their CSV has ~83,000,000 (the clock problem, section 4) |

**Important:** the published code is **not exactly the version that made the CSV**: the CSV has columns this code
does not produce (`flow_duration`, `Magnitue`, `Radius`, `Covariance`, `Weight`), and `Header_Length` / `IAT` don't
match their own formulas. So for those columns we can't know the real formula -> **don't use them**.

---

## 3. Which features match ours? (measured 16 Nov, Docker)

**Q: Which of our feature values are different from theirs?**

Test: our live code recorded **295 rows of a SYN flood and 321 rows of a UDP flood** in Docker. Each feature was
compared with the dataset's SYN / UDP flood rows ("matches" = our value is inside the dataset's normal 5%-95% range).

- **Match (25 of 30):** all flags, `Protocol Type`, `TCP`, `UDP`, `ICMP`, `IPv`, the app ports, and all sizes
  (`Min`, `Max`, `AVG`, `Std`, `Tot size`). Example: a bare SYN = **54 bytes** in theirs and ours; a UDP flood packet
  = **50 bytes** in theirs and ours.
- **Don't match:**

| Feature | Ours | Dataset |
|---|---|---|
| `LLC` | 0 | 1 in 99.99% of all rows |
| `Rate` | 0 | SYN flood ~5, UDP flood ~8,000 |
| `Header_Length` (UDP) | 42 | ~22,825 |
| `flow_duration` | 0 | UDP ~0.07 |

Note: even their `Rate` looks odd (UDP flood ~8,000/s is believable, SYN flood ~5/s is not). Check before trusting it.

---

## 4. IAT: the "clock" feature, and why we dropped it

**Q: IAT should be the time gap between 2 packets. How could it be ~99% of the importance and tell SYN flood from UDP
flood from brute force?**

- **What IAT should be:** the gap between 2 packets (the README says so too). A flood has tiny gaps, a sensor ~2 s.
- **What the CSV contains:** numbers like **83,000,000** for every flood, **166,000,000** for Recon / Web, **0.05-0.09**
  for benign / brute force. Those are not gaps. They follow **when each attack was recorded**.

**Clock example:** SYN flood recorded 10:00-11:00 -> its IAT values sit in range A. UDP flood recorded 11:00-12:00 ->
range B. The model learns "range A = SYN flood". It never looks at the attack itself. Like a student who memorized
"question 7 is always B".

This is called **data leakage** / a **shortcut feature**. On the Pi, a SYN flood at 3 pm gives a "time" the model has
never seen -> nonsense. Measured (`START.md`):

| | With IAT | Without IAT |
|---|---|---|
| Binary (attack or not) | ~99.4% | ~99.4% |
| 8-class (which attack) | ~99.5% | ~91% |

---

## 5. How does the model "know" which rows are ours? It doesn't, it just finds the easiest split

**Q: How would the model know rows were made by their formula or ours? Can't it just learn low pps = benign?**

The model knows nothing about "who made the row". It looks for **any column that splits benign from attack**, and
takes the easiest one. Example with `LLC`:
- Every dataset row has `LLC = 1`, attacks included.
- Our recorded NodeMCU rows would have `LLC = 0`.
- Add our rows as benign -> the easiest rule is **"LLC = 0 -> benign"**: one question, 100% right on the training data.
- But your hping3 flood on the Pi **also has `LLC = 0`** -> called benign -> **attack missed**.

**Fix:** use only features that match (section 3). Then no column is left where our rows look different from theirs,
and the model has to learn the real thing (sizes, flags, protocol). Your "low pps = benign" idea is right in spirit,
but only works if pps is computed the same way in every training row.

---

## 6. Why do we need rules at all? The dataset has no addresses

**Q: Shouldn't the dataset contain features for DDoS (many sources -> one target), spoofing, brute force?**

Checked: the CSV header has **no source IP, no destination IP, no MAC**. A row is the averaged shape of a group of
packets; it doesn't know who sent them.

| Attack | Why the model can't learn it | Our answer |
|---|---|---|
| DDoS vs DoS | Needs "how many senders". From one sender they look identical: UDP flood DDoS vs DoS = protocol 17 vs 17, size 50.0 vs 50.2 | `FloodCounter`: 3+ senders within 10 s = DDoS |
| ARP spoofing | `MITM-ArpSpoofing` rows: median ARP = 0, mostly normal forwarded TCP. No MAC column | `AddressWatcher`: one MAC claiming another's IP, or many IPs |
| Brute force | 290 rows (validation), not MQTT | `BruteForceRule`: 5 refused MQTT logins in 10 s |
| Port scan vs flood | "many ports vs one port" needs port numbers; not a feature | `PortScanRule`: > 20 ports in 5 s |

**Would IP columns help? No, they would hurt.** The model would memorize "IP 192.168.x.y = attacker" from THEIR lab.
On our network the addresses differ. That is why researchers delete IP columns (another shortcut, like IAT).

**Other datasets?** Mendeley "Derived CICIoT2023" = the same rows, pre-sampled (same problems). CICIoMT2024 = same lab,
same style, has MQTT attacks, but medical devices and not in the proposal. Edge-IIoTset / TON_IoT / Bot-IoT have IP
columns (see above: not useful). **Decision: stay with CICIoT2023** (the proposal names it); others = future work.

---

## 7. Why are there so many more DDoS rows than DoS rows?

**Q: DoS and DDoS should be the same attacks with more senders, so why so many more DDoS rows?**

Counted in `validation.csv`:

| | Attack types | Rows |
|---|---|---|
| DDoS | **12** (ICMP, UDP, TCP, PSH-ACK, SYN, RST-FIN, SynonymousIP floods, 3 fragmentation floods, HTTP flood, SlowLoris) | **857,523** |
| DoS | **4** (UDP, TCP, SYN, HTTP flood) | **203,450** |

Two reasons:
1. **More attack types:** 12 DDoS vs 4 DoS. ICMP, PSH-ACK, RST-FIN and the fragmentation floods were only recorded as
   DDoS.
2. **A row = a group of packets, not one attack.** Many attackers at once send many more packets per minute -> many
   more rows for the same recording time. Same attack, same type: DDoS-UDP 136,466 rows vs DoS-UDP 83,446.

For us it doesn't matter: both go into one class, **Flood**, and the rule counts the senders.

---

## 8. Why the NodeMCUs were never flagged, but my SSH was

**Q: The model never saw MQTT traffic, so why doesn't it flag the NodeMCUs, while it did flag my SSH session?**

**Because the model never looks at the NodeMCUs.**
- The model only judges a sender once it has **10 packets within 5 seconds** (`settings.py`).
- A NodeMCU sends **one reading every 2 seconds** (firmware: `millis() - lastReading >= 2000`). That's 2-3 packets in
  5 s -> the window never fills -> thrown away (`windows.py`: "KNOWN LIMITATION: senders slower than ~2 packets/s are
  never classified").
- So their traffic was never called "benign". It was **never judged at all**.

**SSH is fast:** every key press, every line of output, every ACK is a packet -> 10 packets in under a second -> judged
-> the model had never seen SSH like mine -> "attack". Fix: `admin <LAPTOP_IP>` skips my SSH (port 22).

**When the NodeMCUs DO get false alarms:** at boot / Wi-Fi reconnect they send a quick burst (ARP, TCP handshake, MQTT
login). That can fill a window -> the 0.3-0.7 false alarms seen in the lab.

**Is MQTT checked at all?** Yes, but by **rules**: refused logins (brute-force rule), which IP is which node (sensor
registry), ports and addresses. **Honest limitation:** a slow attack (< 10 packets in 5 s) is never seen by the model.

**Why "Recon" and not "port scan"?** Recon (reconnaissance = "looking around before attacking") is the dataset's
**family name** for 5 attacks (port scan, OS scan, host discovery, ping sweep, vulnerability scan). The model only knows
the family. The port-scan rule knows it's a port scan but uses the family name so the dashboard groups them; its reasons
show "different ports: 1024".

---

## 9. Why the bots get "Recon" / "Web" around a flood (Docker, 16 Nov)

**Q: Why do the bots get "Recon" (and "Web") during their floods?**

- The bot UDP flood **was** detected: the 100-packet windows said `DoS flood`, then `DDoS flood (3 senders)`.
- The wrong names came only from the **10-packet windows** of the same traffic. Our notes say flood rows were made
  from 100 packets, so the model never saw a 10-packet piece of a flood and picks the nearest 10-packet family.
  (Their published code uses 10 packets per row: check this on the data before changing the windows.)
- Two things make those small windows look like Recon / Web:
  - **at the start of a flood the connection counters are still small** (Recon-like);
  - **at the start / end, normal MQTT (TCP) and flood packets (UDP) mix** -> `Protocol Type` 12.6 (Web rows sit
    around 8-9). With the "mode" fix (section 2) this would be 6 or 17 instead.
- Low confidence (0.5-0.8) -> only rate-limited; the real Flood alert quarantines the bot anyway.
- `172.30.0.30` Recon alarms in Docker = the **dashboard container** (Docker runs without `admin`).

---

## 10. RQ1 in plain words: how many features do we need?

**Q: What is RQ1, what does "6 points below" mean, and isn't 10 features (or 7, like my thesis) enough?**

**RQ1 (the professor's question):** how few features can we use and still be almost as good as with all of them?

Example: you identify fruit with 45 measurements and are right 70.5 times out of 100. With only the 10 best
measurements, are you still right ~70 times, or does it drop?

The score is **macro-F1** ≈ "how often it names the attack correctly, averaged over all attack types" (1.0 = perfect).
Measured by my friend, without IAT (`model/results_run2/rq1_f1_vs_features.csv`, LightGBM):

| Features | Macro-F1 |
|---|---|
| 5 | 0.568 |
| 10 | **0.645** |
| 15 | 0.675 |
| 20 | 0.676 |
| 30 | 0.685 (first within 2 points of all) |
| all 45 | 0.705 |

- 10 features = 64.5 vs 70.5 with all = **6 points lower**; the proposal wants "within 2%". So for the **many-attacks
  task**, ~30 features are needed. That is the honest RQ1 answer for the dataset.
- **But that task is hard** (telling SQL injection from XSS, OS scan from ping sweep, …). **Our demo only needs**
  attack-or-not and Flood / Recon, which are very different traffic -> **7-10 features is very likely enough**, like
  my thesis. *Not measured yet: needs one retrain.*
- In the report: both numbers. "RQ1 on the dataset: ~30 features for 34 attack types; for our gateway: N features
  give score X."
- Note: that ranking includes features we can't compute live (`Magnitue`, `Number`, `Tot sum`, `syn_count`,
  `Variance`). Our set must come from the matching ones (section 3).

**Useless features for us:** always 0 (or always 1) for both our floods, ours and theirs: `DNS, Telnet, SMTP, SSH,
IRC, HTTP, HTTPS, DHCP, ARP, ece_flag_number, cwr_flag_number, IPv, LLC`. Cheap (0/1), but they don't help.

---

## 11. Did we use validation.csv?

**Yes.** `model/make_ids_models.py` and `make_small_models.py` train on 20% of `train.csv`, use 20% of
`validation.csv` for **early stopping** (stop adding trees when validation stops improving) and to **pick the small
model's size**, and report the final score on `test.csv`. Train = learn, validation = tune, test = final honest score.

---

## 12. The plan: our own benign rows + a small feature set

**Q: Can we record our own NodeMCU traffic (10 fake sensors in Docker), add it as benign, retrain, and drop the
"10 packets in 5 seconds" rule?**

**The plan (not done yet):**
1. **Features:** keep only the ones that match (~10-14):
   `Protocol Type` (fixed to "most common"), `Tot size`, `Min`, `Max`, `AVG`, `Std`, `syn_flag_number`,
   `ack_flag_number`, `psh_flag_number`, `rst_flag_number`, `fin_flag_number`, + `TCP` / `UDP` / `ICMP`.
   Drop `LLC`, `Header_Length`, `flow_duration`, `IAT`. Add **pps** only if computed the same way in every training row.
2. **Families:** drop Web and Mirai -> Benign / Flood / Recon (+ rules for the rest), as in the box at the top.
3. **Our own rows:** record normal sensors (Docker, 10 sensors) **and** the real NodeMCUs in the lab, and **add** them
   to the dataset as benign. Also add a few of our own attack rows (hping3 / nmap in Docker).
4. **Windows:** optionally replace "10 packets within 5 s" with "**every 2 seconds, whatever each sender sent**". Then
   the NodeMCUs are judged too (that's why step 3 is needed).
5. Retrain, test in Docker (NodeMCUs quiet? attacks caught?), then the lab.

**Pros**
- No more false alarms on the NodeMCUs (they are in the training data).
- Every feature means the same thing live and in training -> live results we can trust.
- Simpler code: fewer features, maybe one window instead of two sizes + timeout.
- Fewer, clearer features are easier to explain in the viva.

**Cons / risks**
- **Replace vs add:** if ONLY our rows are benign and ONLY their rows are attacks, the model may split on any leftover
  difference and call our hping3 attacks benign. Adding our own attack rows prevents that.
- **Docker sensors ≠ NodeMCU exactly** (Python vs the ESP chip: packet sizes, timing differ a bit) -> also record the
  real NodeMCUs in the lab.
- **Poisoning:** if an attack happens while recording "benign", the model learns that attack as normal. Record only on a
  clean network.
- **The scores change:** with our own rows mixed in, report dataset scores and our-traffic scores **separately** (the
  proposal's validity note asks for this).
- **Work:** a record mode (~20 lines), feature + family changes (~30-50 lines in `features.py`,
  `make_small_models.py`), retraining (friend's part or me), retesting. About 1-2 days.
- **Fragmentation floods:** `hping3 -f` can send them, but we have never tested them; trusting the model to recognize
  them (no new rules).

**Calibration instead of retraining (cheaper, smaller fix):** record normal traffic, look at the highest "attack
probability" it gets, and set `attack_threshold` in `settings.py` just above it. The model is untouched; only the line
for "attack" moves.

---

## 13. Viva answers (short)

- **Data:** "The CSV rows are computed from packet captures by the authors' script; our gateway computes the same
  columns live. We checked their code and our numbers and kept only the features that are computed the same way."
- **IAT:** "It encodes when each attack was recorded, not how it behaves: a shortcut. With it 99.5%, without 91%, honestly."
- **Rules:** "The dataset has no IP or MAC addresses, so DDoS (how many senders), spoofing (does the MAC fit the IP),
  port scans (how many ports) and MQTT brute force (refused logins) are checked with simple, explainable rules."
- **RQ1:** "For 34 attack types about 30 features are needed to stay within 2%; for our gateway's job (benign / flood /
  recon) a small set of ~10 matching features is enough."
- **Limitation:** "The model only judges senders that fill a window; slow traffic is handled by rules."
