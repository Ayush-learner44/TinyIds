# Data and model: the essential questions (17-18 Nov 2026)

Short answers for the viva. All numbers are measured (dataset: our copy in `../project/dataset/archive/CICIOT23/`;
training: `train_model14.ipynb` = `training/train.py`; lab: `RESULTS.md`). Paths are relative to the `retrain/` folder.

---

## 1. How big is the dataset, and what is in it?

| | train.csv | validation.csv | test.csv | **Total** |
|---|---|---|---|---|
| **Rows** | **5,491,971** | **1,176,851** | **1,176,851** | **7,845,673** |
| Benign | 129,538 (2.36%) | 27,519 (2.34%) | 27,709 (2.35%) | **184,766 (2.36%)** |
| DDoS | 3,998,500 (72.81%) | 857,523 (72.87%) | 855,981 (72.73%) | 5,712,004 (72.80%) |
| DoS | 950,656 (17.31%) | 203,450 (17.29%) | 204,245 (17.36%) | 1,358,351 (17.31%) |
| Mirai | 309,768 (5.64%) | 66,091 (5.62%) | 66,749 (5.67%) | 442,608 (5.64%) |
| Recon | 41,617 (0.76%) | 9,015 (0.77%) | 8,812 (0.75%) | 59,444 (0.76%) |
| Spoofing | 57,530 (1.05%) | 12,306 (1.05%) | 12,410 (1.05%) | 82,246 (1.05%) |
| Web | 2,821 (0.05%) | 657 (0.06%) | 626 (0.05%) | 4,104 (0.05%) |
| BruteForce | 1,541 (0.03%) | 290 (0.02%) | 319 (0.03%) | 2,150 (0.03%) |

- Split **70 / 15 / 15**, the same family shares in every split. All 34 labels in each split.
- **Only 2.36% of rows are benign.** DDoS + DoS = **90%** of everything.
- The full CICIoT2023 is ~46 million rows; our copy is a **7.85 million** row subset of it.
- Every row has its exact attack name (34 labels, e.g. `DDoS-SYN_Flood`, `Recon-PortScan`, `MITM-ArpSpoofing`).
  We group them into 3 classes ourselves.

---

## 2. "9 lakh rows" vs "5.5 million rows": are we training on a subset?

Yes. Both numbers are true:
- `train.csv` has **5.49 million** rows.
- We keep only the **Benign, Flood and Recon** rows: **4,546,831**.
- Of those we take a **random 20% sample, with the same mix of attacks**: **909,368 rows** (the "9 lakh").
- We add **our own 36,255 rows** (Docker + lab). Training total: **945,623 rows**.

**What is in the training data:**

| Class | From the dataset (20% sample) | Ours (Docker + lab) | Total |
|---|---|---|---|
| Benign | 25,908 | 2,599 | **28,507** |
| Flood | 878,334 | 33,487 | **911,821** |
| Recon | 5,126 | 169 | **5,295** |

So our benign rows are **added on top of** 25,908 dataset benign rows, not alone. (We recorded 3,747 benign rows in
total; 70% went to training, the rest to validation and test.) The exact rows: `evaluation_matrices/dataset/train.csv`.

**Why 20% and not 100%?** For LightGBM, 900,000 rows is already a lot. Early stopping (the validation set) stops adding
trees once the score stops improving, so 5x more rows mostly means 5x longer training, not a better model.
"Train on 100%" = use all 4.55 million kept rows instead of 20%; if the scores barely change, that proves 20% is
enough (not done yet).

---

## 3. Will it overfit or underfit?

- **Underfit** = too simple, bad on everything. **Not our case:** floods are caught 99.9% (our test rows) and
  99.7% (dataset test rows).
- **Overfit** = learned its training data too exactly, bad on new data. **Not badly:** the final lab run used FRESH
  attacks the model had never seen: every attack was detected, and 0 false alarms on the 3 NodeMCUs.
- **The real weakness is imbalance:** Recon is only ~0.6% of the training rows, so it is the weakest class on the
  dataset (~0.30 recall). Class weights help (each rare row counts more) but don't fully fix it.

**"99.9% / 99.7%" is not imbalance.** It is **recall**: of all flood rows, how many were caught.
**Imbalance** = how many rows each class has: in training Flood ~96%, Benign ~3%, Recon ~0.6%. **Class weights**
stop the model from simply answering "Flood" every time.

---

## 4. What does the model do, and what do the rules do?

| Attack | Model or rule | How |
|---|---|---|
| Benign / Flood / Recon | **Model** (one model, 3 answers) | packet shape: sizes, flags, protocol |
| SYN / UDP / ICMP / ACK / PSH-ACK / RST-FIN | **Model** says "Flood" | no subtype name; the **SHAP reasons** show it (`UDP`, `ICMP`, `psh_flag_number` ...) |
| DoS vs DDoS | **Rule** | counts senders (2+ = DDoS) |
| Port scan | **Model** (Recon) **+ rule** (> 20 ports in 5 s) | both fired in the lab |
| MQTT brute force | **Rule** | 5 refused logins in 10 s |
| ARP / IP spoofing | **Rule** | MAC and IP must match |

**Recon in the lab (17 Nov):** port scan and version scan correct, Recon 0.99. The OS scan was named "Flood", but it
was blocked at once. More nmap recordings (including `-O`) would help Recon (optional).

---

## 5. Why mix our benign rows with the dataset's benign rows?

CICIoT2023 was recorded in a lab with **105 IoT devices** (cameras, smart plugs, speakers, sensors ...). (How many of
them produced the benign rows exactly: not known to us.) Their benign traffic gives the model **variety**. Ours adds
the one thing it had never seen: **our NodeMCUs' MQTT**. Before we added ours, the real NodeMCUs got false "Recon"
alarms; after, zero.

---

## 6. Why not use the dataset for spoofing and DDoS?

**The rows have no IP or MAC addresses.**
- **DDoS:** from one sender, a DoS row and a DDoS row look the same (UDP flood: same protocol, size 50 vs 50.2).
  The only difference is **how many senders**, and a row can't know that -> a rule counts them.
- **ARP spoofing:** the attack is "a MAC claims an IP that belongs to another MAC". With no MAC column the model
  can't see it. Their spoofing rows are mostly normal forwarded traffic (median ARP = 0).

---

## 7. What did we remove, and why?

Of the dataset's 34 labels we train on **13**: BenignTraffic, 9 floods (DDoS/DoS SYN, UDP, ICMP, TCP, PSH-ACK,
RST-FIN) and 3 scans (PortScan, OSScan, VulnerabilityScan). The other 21 are left out:

| Removed | Why |
|---|---|
| **Web** (SQL injection, XSS, command injection, backdoor, browser hijacking, uploading: 6) | needs a web server; the Pi has none, so it can't be attacked or tested that way. Also tiny: 0.05% of rows |
| **Mirai** (greeth, greip, udpplain: 3) | needs real Mirai malware; our NodeMCU bots already make real DDoS floods |
| **Spoofing** (ARP, DNS: 2) | no MAC / IP columns, so the rows can't show it (section 6) -> **rule** |
| **Brute force** (1) | it is not MQTT (our broker), only 1,541 rows -> **rule** (refused MQTT logins) |
| HTTP flood (DoS + DDoS), SlowLoris (3) | need a web server |
| SynonymousIP flood, ICMP / UDP / ACK fragmentation (4) | we never recorded or tested them on our testbed, so we could not check our features match for them. Kept out to stay simple |
| Ping sweep, host discovery (2) | they send < 10 packets to the Pi: never a full window of 10, the model never even sees them |

**Does the model still catch the ones it was never trained on?** Measured on the dataset's test rows
(`evaluation_matrices/REPORT.md`, section B): Mirai floods **99.1-99.4%**, SynonymousIP **99.9%**, ICMP fragmentation
**97.7%** (they look like floods, so it calls them Flood). UDP fragmentation 66%, ACK fragmentation 44%, HTTP floods
40-61%. Web attacks, brute force, spoofing: **0-15%** (as expected: they look like normal traffic; rules or out of
scope).

---

## 7b. Why combine all the floods into ONE class "Flood"?

The dataset has 9 flood labels (+ 3 Mirai). We merged them into one class, for 4 reasons:

1. **The response is the same.** Whatever the flood type, the Pi does one thing: block the sender. Knowing "SYN" vs
   "UDP" doesn't change the action.
2. **The type is still visible.** The SHAP reason in every alert names it: `syn_flag_number` = SYN flood, `UDP` = UDP
   flood, `ICMP` = ping flood, `psh_flag_number` = PSH-ACK (section 8 table).
3. **DoS vs DDoS can't be learned from one row.** The only difference is how many senders, and rows have no IP
   (section 6). A per-label model would be guessing; the sender-counting rule answers it exactly.
4. **Fewer classes = smaller, more reliable model.** 3 classes fit in < 1 MB with good scores; the old project's
   8-class model reached only ~0.70 macro-F1, and 34 classes even less, mostly by confusing look-alike attacks.

The same for Recon: port scan, OS scan and vulnerability scan become one class **Recon**.

---

## 7c. How exactly was the model trained? Pruned? Quantized?

**Code:** `train_model14.ipynb` (in `retrain/`, step by step with explanations) = the same as `training/train.py`.
Running the notebook rebuilds **exactly** the deployed `pi/models/top14/model.txt` (checked 18 Nov: identical trees).

| Setting | Value | Why |
|---|---|---|
| Model | **LightGBM** (gradient-boosted decision trees), 3 classes | fast and small on the Pi; SHAP explanations are exact and cheap for trees |
| Training rows | 945,623 (909,368 dataset + 36,255 ours) | section 2 |
| Tree size | `num_leaves` 15, `max_bin` 63 | small trees = small file, fast on the Pi |
| Number of trees | up to 300 per class, **early stopping** after 20 rounds without improvement on the validation rows -> **189** | stop before it overfits |
| Class weights | sqrt of inverse class share | Recon is rare; without weights it would be ignored |
| Randomness | bagging 0.8, feature_fraction 0.8, seed 0 | less overfitting, same result every run |
| Decision rule | P(attack) = 1 - P(Benign); below **0.70** -> Benign | fewer false alarms on our sensors |
| File size | **974 KB** (< 1 MB target) | |

- **Pruning: yes, in the tree sense.** Small trees (15 leaves), early stopping, and a size cap (if the file is >= 1 MB,
  trees are cut from the end until it fits; here it was not needed, 974 KB at 189 trees).
- **Quantization (INT8): no, not for this model.** A tree model stores split thresholds, not big weight matrices;
  it is already < 1 MB and ~1 ms per window on the Pi, so there was nothing to gain. INT8 was done in the old project
  for the MLP and 1D-CNN (`../project/model/fresh/RESULTS.md`): 58-86 KB, about the same accuracy, but NOT faster
  one row at a time. Those nets are not deployed.

---

## 7d. Where is everything? (data, model, code, results)

| What | Where |
|---|---|
| The full dataset (CICIoT2023, 7.85 M rows) | `../project/dataset/archive/CICIOT23/` (csv), `../project/model/cache/` (parquet, faster) |
| **The exact rows the model was trained / tested on** | `evaluation_matrices/dataset/` (train, validation, test_dataset, test_ours csv) |
| Our own recordings (raw) | `training/data/*.csv` (25 recordings: Docker testbed + real Pi lab) |
| **Training code** | `train_model14.ipynb` (notebook), `training/train.py` (script, also trains 5/7/10-feature versions) |
| **The model** | `pi/models/top14/` (`model.txt` + `meta.json` = feature list, classes); copy in `evaluation_matrices/model/` |
| Training output (scores, feature ranking) | `training/train_report.txt` |
| **Evaluation** (confusion matrices, precision/recall/F1, ROC, every attack type, speed, size) | `evaluation_matrices/REPORT.md` + `evaluation_matrices/images/`, made by `evaluation_matrices/evaluate.py` |
| Live tests on the real Pi (every attack, alerts, RAM) | `RESULTS.md`, logs in `laptop/` |
| Why these features (measured comparison ours vs dataset) | `dataset.md` sections 3-4

---

## 8. Which features does the model use, and for which attacks?

**14 of the dataset's 46 features.** One model; it looks at all 14 for every decision. The second table shows which
features mattered most (SHAP top-3, live on the real Pi, 17 Nov).

**The 14 features we use**

| # | Feature | Meaning (per window of 10 packets) |
|---|---|---|
| 1 | `Protocol Type` | most common protocol (6 = TCP, 17 = UDP, 1 = ICMP) |
| 2 | `TCP` | share of TCP packets |
| 3 | `UDP` | share of UDP packets |
| 4 | `ICMP` | share of ICMP (ping) packets |
| 5 | `syn_flag_number` | share of packets with the SYN flag |
| 6 | `ack_flag_number` | share with ACK |
| 7 | `psh_flag_number` | share with PSH |
| 8 | `rst_flag_number` | share with RST |
| 9 | `fin_flag_number` | share with FIN |
| 10 | `Min` | smallest packet size |
| 11 | `Max` | largest packet size |
| 12 | `AVG` | average packet size |
| 13 | `Std` | how much the sizes vary |
| 14 | `Tot size` | average packet length |

**Which features decided each attack** (SHAP top-3 on the real Pi)

| Attack | Main features |
|---|---|
| UDP flood | `Protocol Type`, `UDP`, `Min` |
| ICMP flood | `ICMP`, `Min` |
| SYN flood | `syn_flag_number`, `Min`, `Std` |
| ACK flood | `Min`, `Max`, `Std` |
| PSH-ACK flood | `psh_flag_number`, `Min`, `Max` |
| RST-FIN flood | `fin_flag_number`, `rst_flag_number`, `Min` |
| Bot TCP flood (DDoS) | `syn_flag_number`, `fin_flag_number`, `rst_flag_number` |
| Port / version scan (Recon) | `AVG`, `Tot size`, `Max`, `Protocol Type` |
| Normal NodeMCU traffic | bigger packets (`Tot size`, `AVG`), PSH / ACK flags |

**The 32 we dropped, and why**

| Reason | Features | Count |
|---|---|---|
| **Computed differently live than in the dataset** (or a bug in their code) | `flow_duration`, `Header_Length`, `Rate`, `Srate`, `Drate`, `Duration` (TTL), `LLC` | 7 |
| **Shortcuts that give away the answer** | `IAT` (capture time), `Number`, `Weight` (window size) | 3 |
| **Count and statistics features we don't compute live** | `ack_count`, `syn_count`, `fin_count`, `urg_count`, `rst_count`, `Tot sum`, `Magnitue`, `Radius`, `Covariance`, `Variance` | 10 |
| **Always 0 (or always 1) for our attacks** | `HTTP`, `HTTPS`, `DNS`, `Telnet`, `SMTP`, `SSH`, `IRC`, `DHCP`, `ARP`, `IPv`, `ece_flag_number`, `cwr_flag_number` | 12 |
| **Total dropped** | | **32** |

**One line:** the model only looks at packet sizes, TCP flags and protocol: 14 numbers per 10 packets, computed exactly
the same way on the Pi as in the dataset, so what it learned in training also works live.

---

## 9. What are train, validation and test for?

Think of a student preparing for an exam:

| Set | Like | What it does for our model |
|---|---|---|
| **Train** | the textbook | the model **learns** from these rows: it sees the 14 numbers and the right answer, and builds its trees |
| **Validation** | practice tests while studying | the model does **not** learn from them. After every new tree we check the score on them; when it stops improving (20 trees in a row), training stops. This stops it from memorising the textbook |
| **Test** | the final exam | **never seen** during training. Used once at the end to report the real score |

Testing on rows the model trained on = giving the student the exam questions in advance: a great score that means
nothing.

---

## 10. Did we split the "9 lakh" again into train / validation / test?

**No.** The dataset authors already split CICIoT2023 into **3 files** (`train.csv`, `validation.csv`, `test.csv`).
We did the same filtering on all three (keep only Benign + 9 floods + 3 scans; web, Mirai, spoofing etc. removed),
and took 20% of only two of them:

| File | After removing the attacks we don't use | Then | Used as |
|---|---|---|---|
| `train.csv` (5.49 M) | 4.55 M | **20%** -> **909,368** (the "9 lakh") | training |
| `validation.csv` (1.18 M) | ~974 K | **20%** -> **194,837** | validation |
| `test.csv` (1.18 M) | 973,829 | **all of it, no 20% cut** | test |

- The 9 lakh comes **only** from the authors' `train.csv`.
- The model did **not** train on anything from validation or test.

---

## 11. Where did our own rows (incl. our NodeMCU benign) go? Were they tested?

We recorded **51,843** rows ourselves (Docker testbed + real Pi lab) and split them at random **70 / 15 / 15**:

| Our rows | Total | Benign (NodeMCU traffic) | Flood | Recon |
|---|---|---|---|---|
| -> train | 36,255 | 2,599 | 33,487 | 169 |
| -> validation | 7,917 | 581 | 7,300 | 36 |
| -> **test** | **7,671** | **567** | 7,065 | 39 |

**Yes, our benign was tested:** 567 of our NodeMCU rows were held out, never trained on. So there are two exams
(`evaluation_matrices/REPORT.md`):
- **Section A:** the dataset's test rows, only *their* benign (27,709 rows): 99.0% correct.
- **Section C:** *our* test rows, split by **time** (section 12): our benign **564 of 564 correct** (0 false alarms),
  floods 99.9%, our scans 78%, macro-F1 **0.945**.

**The catch with the random split:** the deployed model's split (the table above, `evaluation_matrices/dataset/`)
was random **per row**. A test row can be from the same recording, a second before or after a training row: almost
the same numbers (an exam question that is nearly a textbook example). That gave a too-good 566 of 567 / macro-F1
0.957. So section C of `REPORT.md` now uses the time split instead (section 12).

**The real independent test is the live lab run:** fresh attacks and fresh NodeMCU traffic, recorded after training,
never seen in any form: every attack detected, **0 false alarms on the 3 NodeMCUs** (`RESULTS.md`, final 17 Nov run).

**Viva line:** "Our held-out rows test it, but the honest independent test is the live lab run."

---

## 12. Why split at random? Couldn't we cut the recordings cleanly?

Each recording is a list of windows in time order: 1, 2, 3, ... 1000. (Every row goes to exactly ONE set; a row is
never in two.)

- **Random split (what we did):** row 501 -> test, but rows 500 and 502 (a fraction of a second before and after,
  same attack, almost the same numbers) -> train. The model has practically seen row 501 already.
- **Time-block split (better):** in every recording, the first 70% of the rows -> train, the next 15% -> validation,
  the last 15% -> test. Then train and test only touch at **one** point per recording, so the test is close to "new
  data".
- **Whole-recording split (strictest):** some recordings only for training, others only for testing.
  Problem for us: several attack types have only 1 recording with very few rows (e.g. `recon_syn`, `recon_version`),
  so some types would be missing from training or from testing.

**Why random then?** It was the default and it is the usual way; with rows that follow each other in time it gives
too-good scores.

**Done (18 Nov): section C of `REPORT.md` now uses the time-block split.** The cut is made separately for the normal
and the attack rows of each recording (nmap finishes early, so the last 15% of a whole scan recording has no scan rows
at all). A model is trained with the same recipe, only with this split, in memory (`evaluate.py`):

| Our test rows | Random split (old) | **Time split (now)** |
|---|---|---|
| Benign (our NodeMCUs) | 566 of 567, 1 false alarm | **564 of 564, 0 false alarms** |
| Flood F1 | 0.999 | **0.999** |
| Recon recall | 0.90 (35 of 39) | **0.78 (31 of 40)** |
| Macro-F1 | 0.957 | **0.945** |

Benign and Flood: no change. Recon was the flattered one: 7 of the 9 missed scan rows were called Flood (as the OS
scan in the live lab: wrong name, but still blocked).

---

## Viva answer

"The model judges **what the traffic looks like**: flood, scan or normal. The **who and how many** questions (DDoS,
spoofing, brute force) need addresses or login results that the dataset doesn't contain, so simple, explainable
rules answer them. We trained on a 20% sample of the dataset's benign, flood and recon rows (909,368) plus 36,255
rows recorded on our own testbed and lab, and checked it live with fresh attacks: everything detected, no false alarms
on our sensors."
