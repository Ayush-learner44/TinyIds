# TinyIDS evaluation (live model `pi/models/top14`)

Model: one LightGBM, 3 classes ['Benign', 'Flood', 'Recon'], 14 features, 974 KB. Decision rule as on the Pi: P(attack) = 1 - P(Benign) >= 0.7 -> attack, then the most likely attack class.

## A. Dataset test rows (CICIoT2023 test.csv, never used in training)

973,829 rows of the kept classes (Benign 27,709, Flood 940,692, Recon 5,428).

**3-class:** accuracy 0.9927, macro-F1 0.7598, weighted-F1 0.9921

| class   |   rows |   precision |   recall |     F1 |
|:--------|-------:|------------:|---------:|-------:|
| Benign  |  27709 |      0.8271 |   0.9903 | 0.9014 |
| Flood   | 940692 |      0.9998 |   0.9968 | 0.9983 |
| Recon   |   5428 |      0.5597 |   0.2874 | 0.3798 |

|             |   pred Benign |   pred Flood |   pred Recon |
|:------------|--------------:|-------------:|-------------:|
| true Benign |         27439 |           59 |          211 |
| true Flood  |          1964 |       937712 |         1016 |
| true Recon  |          3771 |           97 |         1560 |

Picture: `images/cm_dataset_test.png`

**Binary (attack vs benign):**

|                         |   value |
|:------------------------|--------:|
| accuracy                |  0.9938 |
| precision (attack)      |  0.9997 |
| recall / detection rate |  0.9939 |
| F1 (attack)             |  0.9968 |
| macro-F1                |  0.9491 |
| false-positive rate     |  0.0097 |
| false-negative rate     |  0.0061 |
| ROC-AUC                 |  0.9986 |

## B. Every one of the 34 dataset labels (test.csv)

`detected` = called an attack at all (Flood or Recon). `right family` = Flood for floods, Recon for scans. Labels marked *not trained* were left out of training on purpose (rules handle them, or they need a web server).

| label                   |   rows | trained on   |   detected as attack |   right family |   false alarm rate |
|:------------------------|-------:|:-------------|---------------------:|---------------:|-------------------:|
| DDoS-ICMP_Flood         | 180447 | yes          |               0.9991 |         0.9989 |           nan      |
| DDoS-UDP_Flood          | 136717 | yes          |               0.998  |         0.9978 |           nan      |
| DDoS-TCP_Flood          | 113735 | yes          |               0.9989 |         0.9982 |           nan      |
| DDoS-PSHACK_Flood       | 103326 | yes          |               0.9987 |         0.9985 |           nan      |
| DDoS-SYN_Flood          | 102208 | yes          |               0.9991 |         0.9978 |           nan      |
| DDoS-RSTFINFlood        | 101819 | yes          |               0.9993 |         0.9992 |           nan      |
| DoS-UDP_Flood           |  83627 | yes          |               0.9916 |         0.9909 |           nan      |
| DoS-TCP_Flood           |  67697 | yes          |               0.9977 |         0.9913 |           nan      |
| DoS-SYN_Flood           |  51116 | yes          |               0.9951 |         0.9908 |           nan      |
| BenignTraffic           |  27709 | yes          |             nan      |         0.9903 |             0.0097 |
| Recon-OSScan            |   2433 | yes          |               0.2454 |         0.2252 |           nan      |
| Recon-PortScan          |   2082 | yes          |               0.3521 |         0.3338 |           nan      |
| VulnerabilityScan       |    913 | yes          |               0.3582 |         0.3472 |           nan      |
| DDoS-SynonymousIP_Flood |  90480 | not trained  |               0.9993 |       nan      |           nan      |
| Mirai-greeth_flood      |  24934 | not trained  |               0.9944 |       nan      |           nan      |
| Mirai-udpplain          |  22536 | not trained  |               0.994  |       nan      |           nan      |
| Mirai-greip_flood       |  19279 | not trained  |               0.9907 |       nan      |           nan      |
| DDoS-ICMP_Fragmentation |  11402 | not trained  |               0.9774 |       nan      |           nan      |
| MITM-ArpSpoofing        |   7840 | not trained  |               0.0925 |       nan      |           nan      |
| DDoS-ACK_Fragmentation  |   7292 | not trained  |               0.438  |       nan      |           nan      |
| DDoS-UDP_Fragmentation  |   7224 | not trained  |               0.6621 |       nan      |           nan      |
| DNS_Spoofing            |   4570 | not trained  |               0.1481 |       nan      |           nan      |
| Recon-HostDiscovery     |   3331 | not trained  |               0.5056 |       nan      |           nan      |
| DoS-HTTP_Flood          |   1805 | not trained  |               0.61   |       nan      |           nan      |
| DDoS-HTTP_Flood         |    709 | not trained  |               0.4006 |       nan      |           nan      |
| DDoS-SlowLoris          |    622 | not trained  |               0.1994 |       nan      |           nan      |
| DictionaryBruteForce    |    319 | not trained  |               0.0251 |       nan      |           nan      |
| SqlInjection            |    148 | not trained  |               0.0473 |       nan      |           nan      |
| BrowserHijacking        |    134 | not trained  |               0.0224 |       nan      |           nan      |
| CommandInjection        |    119 | not trained  |               0      |       nan      |           nan      |
| XSS                     |    103 | not trained  |               0      |       nan      |           nan      |
| Backdoor_Malware        |     89 | not trained  |               0.0225 |       nan      |           nan      |
| Recon-PingSweep         |     53 | not trained  |               0.1132 |       nan      |           nan      |
| Uploading_Attack        |     33 | not trained  |               0      |       nan      |           nan      |

## C. Our own recorded rows (Docker testbed + real Pi lab), TIME split: the last 15% of every recording

7,789 rows (Benign 564, Flood 7,185, Recon 40).

**How:** each recording is in time order. For every recording (and separately for its normal and attack rows) the first 70% of the rows were used for training, the next 15% for validation, and the **last 15%** for this test. Train and test only touch at one point in time, so the test is close to new data. (A random row split would put near-identical neighbouring windows in both, which makes the score too good: macro-F1 0.957 instead of the honest number below.) For this, a model was trained with exactly the same recipe and dataset rows as the deployed one, only with our rows split by time (300 trees, in memory only). The live lab runs (RESULTS.md) remain the fully independent test.

**3-class:** accuracy 0.9983, macro-F1 0.9448

| class   |   rows |   precision |   recall |     F1 |
|:--------|-------:|------------:|---------:|-------:|
| Benign  |    564 |      0.9947 |   1      | 0.9973 |
| Flood   |   7185 |      0.999  |   0.9994 | 0.9992 |
| Recon   |     40 |      0.9118 |   0.775  | 0.8378 |

|             |   pred Benign |   pred Flood |   pred Recon |
|:------------|--------------:|-------------:|-------------:|
| true Benign |           564 |            0 |            0 |
| true Flood  |             1 |         7181 |            3 |
| true Recon  |             2 |            7 |           31 |

Picture: `images/cm_our_rows.png`

**Binary (attack vs benign):**

|                         |   value |
|:------------------------|--------:|
| accuracy                |  0.9996 |
| precision (attack)      |  1      |
| recall / detection rate |  0.9996 |
| F1 (attack)             |  0.9998 |
| macro-F1                |  0.9986 |
| false-positive rate     |  0      |
| false-negative rate     |  0.0004 |
| ROC-AUC                 |  1      |

**Per recording (test rows only):**

| recording           |   rows |   correct |   benign rows flagged |
|:--------------------|-------:|----------:|----------------------:|
| benign              |    156 |    1      |                     0 |
| benign_plain        |    246 |    1      |                     0 |
| flood_ack           |    397 |    1      |                     0 |
| flood_bots_lab_tcp1 |    111 |    1      |                     0 |
| flood_bots_lab_tcp2 |    119 |    1      |                     0 |
| flood_bots_lab_tcp3 |    138 |    1      |                     0 |
| flood_bots_lab_udp1 |    127 |    1      |                     0 |
| flood_bots_tcp_1    |    743 |    0.9987 |                     0 |
| flood_bots_tcp_2    |    754 |    0.9973 |                     0 |
| flood_bots_tcp_3    |    753 |    0.9987 |                     0 |
| flood_bots_udp_1    |    979 |    1      |                     0 |
| flood_icmp          |    401 |    1      |                     0 |
| flood_lab           |    710 |    1      |                     0 |
| flood_pshack        |    397 |    1      |                     0 |
| flood_rstfin        |    408 |    1      |                     0 |
| flood_syn           |    753 |    1      |                     0 |
| flood_syn_slow      |     91 |    1      |                     0 |
| flood_udp           |    394 |    1      |                     0 |
| recon_connect       |     10 |    1      |                     0 |
| recon_lab           |     75 |    0.9067 |                     0 |
| recon_os            |      8 |    0.875  |                     0 |
| recon_ping          |      3 |    1      |                     0 |
| recon_syn           |      7 |    1      |                     0 |
| recon_version       |      5 |    1      |                     0 |
| recon_vuln          |      4 |    0.75   |                     0 |

## D. Size, speed, explanation time, feature importance

| measure                    | laptop   | Raspberry Pi (lab, measured live)   | target   |
|:---------------------------|:---------|:------------------------------------|:---------|
| model file size            | 974 KB   | same file                           | < 1 MB   |
| prediction time per window | 0.19 ms  | ~0.7-1.4 ms (dashboard)             | < 5 ms   |
| SHAP time per alert        | 1.56 ms  | ~5-14 ms (dashboard)                | < 50 ms  |
| RAM of the whole detector  | -        | 77-78 MB                            | < 100 MB |

| feature         |   mean |SHAP| |             gain |
|:----------------|--------------:|-----------------:|
| AVG             |         1.427 |      2.23232e+06 |
| ICMP            |         1.244 |   9136           |
| Protocol Type   |         1.051 | 274289           |
| Tot size        |         0.747 |      1.03714e+06 |
| ack_flag_number |         0.736 | 170329           |
| Max             |         0.691 | 166508           |
| Min             |         0.639 |  93018           |
| psh_flag_number |         0.562 |  42201           |
| fin_flag_number |         0.522 |  34882           |
| Std             |         0.474 |  59494           |
| TCP             |         0.469 |  23035           |
| rst_flag_number |         0.309 |  94759           |
| UDP             |         0.308 |   3956           |
| syn_flag_number |         0.294 |  95258           |

Picture: `images/feature_importance.png`

## E. RQ1: how many features? (5 / 7 / 10 / 14, same training, dataset test rows)

|   features |   dataset macro-F1 |   dataset binary F1 (attack) |   dataset Recon recall |   our rows macro-F1 |   size KB |
|-----------:|-------------------:|-----------------------------:|-----------------------:|--------------------:|----------:|
|          5 |             0.646  |                       0.9939 |                 0.073  |              0.8767 |       973 |
|          7 |             0.722  |                       0.9958 |                 0.2139 |              0.938  |       976 |
|         10 |             0.7541 |                       0.9966 |                 0.2846 |              0.693  |       973 |
|         14 |             0.7598 |                       0.9968 |                 0.2874 |              0.9648 |       974 |

Picture: `images/rq1_features.png`

## F. RQ1 as in the proposal: top 5 / 10 / 15 / 20 / 25 / 30 / all 45 features (offline, dataset only)

|   features |   dataset macro-F1 |   dataset binary F1 (attack) |   dataset Recon recall |   size KB | Pi can compute all   | within 2% of all-45   |
|-----------:|-------------------:|-----------------------------:|-----------------------:|----------:|:---------------------|:----------------------|
|          5 |             0.8074 |                       0.9982 |                 0.3968 |      1520 | False                | False                 |
|         10 |             0.8631 |                       0.9985 |                 0.5324 |      1540 | False                | False                 |
|         15 |             0.8792 |                       0.9986 |                 0.5857 |      1540 | False                | True                  |
|         20 |             0.8819 |                       0.9986 |                 0.5894 |      1541 | False                | True                  |
|         25 |             0.8837 |                       0.9986 |                 0.5941 |      1542 | False                | True                  |
|         30 |             0.884  |                       0.9986 |                 0.5943 |      1544 | False                | True                  |
|         45 |             0.8851 |                       0.9986 |                 0.5965 |      1535 | False                | True                  |

**Answer (3-class task, dataset):** all 45 features give macro-F1 0.8851; the smallest tested set within 0.02 of that is **15 features** (0.8792). For comparison, the deployed 14 Pi-computable features give 0.7598 (section E; that model is also trained on our own rows).

SHAP ranking of all 45 (most important first; **bold** = one of the 14 the Pi computes like the dataset):

Number, Rate, Magnitue, **Min**, fin_count, flow_duration, syn_count, **Protocol Type**, **TCP**, ack_count, **rst_flag_number**, Header_Length, rst_count, Srate, Weight, **Tot size**, **Max**, **syn_flag_number**, Variance, Duration, urg_count, Radius, **ack_flag_number**, **psh_flag_number**, **AVG**, Tot sum, HTTP, HTTPS, **fin_flag_number**, **UDP**, Covariance, **Std**, **ICMP**, DNS, ARP, IPv, LLC, Drate, cwr_flag_number, ece_flag_number, DHCP, SSH, IRC, SMTP, Telnet

Picture: `images/rq1_all45.png`  (section F took 106 s)

ROC picture (A + C): `images/roc_attack_vs_benign.png`

_Evaluation took 143 s._
---

## What the words mean (plain English)

- **Confusion matrix:** rows = the truth, columns = what the model said. The diagonal = correct. Example: "true Recon,
  pred Benign 3,771" = 3,771 scan rows the model thought were normal.
- **Precision (for a class):** when the model says "Flood", how often it really is a flood.
- **Recall / detection rate:** of all real floods, how many the model caught.
- **F1:** one number combining precision and recall (1.0 = perfect).
- **Macro-F1:** the average F1 of the classes, each class counting the same (so the small Recon class pulls it down).
- **Weighted-F1:** the same average, but big classes count more.
- **False-positive rate:** share of NORMAL rows wrongly flagged as attack (false alarms).
- **False-negative rate:** share of ATTACK rows the model missed.
- **ROC-AUC:** how well the attack probability separates attack from normal over all thresholds (1.0 = perfect,
  0.5 = coin flip).

## Summary for the report

- **Is it an attack? (binary):** dataset test F1 **0.997**, detection rate **99.4%**, false alarms **0.97%**, ROC-AUC
  **0.999**. Target "binary F1 >= 0.98": **met**.
- **Floods:** recall **99.7%** (every flood type 99.1-99.9%), precision 99.98%.
- **Benign:** 99.0% recognised; on our real NodeMCU rows (time split, last 15% of every recording) **0 of 564**
  flagged.
- **Recon (scans):** the weak class on the dataset: recall **29%** (most dataset scan rows look like normal traffic
  with these 14 features). On our own scans (time split) **78%**. Live in the lab, our nmap port and version scans
  were detected (0.99), plus the port-scan rule.
- **Attacks we did not train on:** Mirai floods and SynonymousIP / ICMP-fragmentation floods are still called attacks
  (97-99.9%), because they look like floods. Web attacks, brute force and spoofing are NOT detected by the model
  (0-15%): that is expected, they are left to rules or out of scope.
- **Size / speed:** 974 KB (< 1 MB), ~1 ms per window and ~5-14 ms SHAP on the Pi, 77-78 MB RAM: all targets met.