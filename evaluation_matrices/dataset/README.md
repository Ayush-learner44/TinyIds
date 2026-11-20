# The exact data the deployed model (`top14`) was trained and tested on

Made by `../../train_model14.ipynb` (step 9). Same rows, same order as `training/train.py` used on 17 Nov.

| File | Rows | Size | Used for |
|---|---|---|---|
| `train.csv` | 945,623 | 105 MB | **training** (the model learned from these) |
| `validation.csv` | 202,754 | 23 MB | early stopping only (decides when to stop adding trees) |
| `test_dataset.csv` | 973,829 | 95 MB | testing: the dataset's own test split, never seen in training |
| `test_ours.csv` | 7,671 | 1 MB | testing: 15% of our own recordings, never seen in training |

Note: `train.csv` and `test_dataset.csv` are close to Excel's 1,048,576-row limit; use pandas
(`pd.read_csv("train.csv")`) rather than Excel.

## Columns

| Column | Meaning |
|---|---|
| `Protocol Type` | most common protocol in the window (6 = TCP, 17 = UDP, 1 = ICMP) |
| `Tot size` | average packet length |
| `Min`, `Max`, `AVG`, `Std` | smallest / largest / average packet size, and how much sizes vary |
| `syn_flag_number`, `ack_flag_number`, `psh_flag_number`, `rst_flag_number`, `fin_flag_number` | share of packets with that TCP flag |
| `TCP`, `UDP`, `ICMP` | share of packets of that protocol |
| `y` | **the class the model learns**: Benign, Flood or Recon |
| `label` | where the row came from: the original CICIoT2023 attack name (e.g. `DDoS-SYN_Flood`), or for our rows the recording file (e.g. `flood_bots_lab_tcp1`) |
| `source` | `CICIoT2023` or `ours` (our Docker testbed + real Pi lab recordings) |

One row = one window of 10 packets. The first 14 columns are the model's input; `y` is the answer it must give.

## How the rows were picked

- **CICIoT2023:** only Benign + the 9 flood + 3 scan labels; 20% random sample of each label for train and
  validation (seed 0 / 1), 100% of the test split.
- **Ours:** all 25 recordings in `../../training/data/`, split 70 / 15 / 15 at random (seed 0) into train / validation
  / test.
- Why these classes and features: `../data_and_model_questions.md`, sections 7, 7b and 8.

## Row counts

### train.csv  (945,623 rows)

| source     |   Benign |   Flood |   Recon |   total |
|:-----------|---------:|--------:|--------:|--------:|
| CICIoT2023 |    25908 |  878334 |    5126 |  909368 |
| ours       |     2599 |   33487 |     169 |   36255 |
| total      |    28507 |  911821 |    5295 |  945623 |

<details><summary>rows per original label / recording</summary>

| source     | y      | label               |   rows |
|:-----------|:-------|:--------------------|-------:|
| CICIoT2023 | Benign | BenignTraffic       |  25908 |
| CICIoT2023 | Flood  | DDoS-ICMP_Flood     | 169618 |
| CICIoT2023 | Flood  | DDoS-PSHACK_Flood   |  96251 |
| CICIoT2023 | Flood  | DDoS-RSTFINFlood    |  95088 |
| CICIoT2023 | Flood  | DDoS-SYN_Flood      |  95731 |
| CICIoT2023 | Flood  | DDoS-TCP_Flood      | 105700 |
| CICIoT2023 | Flood  | DDoS-UDP_Flood      | 127512 |
| CICIoT2023 | Flood  | DoS-SYN_Flood       |  47515 |
| CICIoT2023 | Flood  | DoS-TCP_Flood       |  62835 |
| CICIoT2023 | Flood  | DoS-UDP_Flood       |  78084 |
| CICIoT2023 | Recon  | Recon-OSScan        |   2317 |
| CICIoT2023 | Recon  | Recon-PortScan      |   1930 |
| CICIoT2023 | Recon  | VulnerabilityScan   |    879 |
| ours       | Benign | benign              |    710 |
| ours       | Benign | benign_plain        |   1161 |
| ours       | Benign | flood_ack           |     15 |
| ours       | Benign | flood_icmp          |     16 |
| ours       | Benign | flood_lab           |    303 |
| ours       | Benign | flood_pshack        |     15 |
| ours       | Benign | flood_rstfin        |     12 |
| ours       | Benign | flood_syn           |     15 |
| ours       | Benign | flood_syn_slow      |     13 |
| ours       | Benign | flood_udp           |     13 |
| ours       | Benign | recon_connect       |     11 |
| ours       | Benign | recon_lab           |    245 |
| ours       | Benign | recon_os            |     15 |
| ours       | Benign | recon_ping          |     10 |
| ours       | Benign | recon_syn           |     17 |
| ours       | Benign | recon_version       |     15 |
| ours       | Benign | recon_vuln          |     13 |
| ours       | Flood  | flood_ack           |   1832 |
| ours       | Flood  | flood_bots_lab_tcp1 |    530 |
| ours       | Flood  | flood_bots_lab_tcp2 |    563 |
| ours       | Flood  | flood_bots_lab_tcp3 |    633 |
| ours       | Flood  | flood_bots_lab_udp1 |    586 |
| ours       | Flood  | flood_bots_tcp_1    |   3461 |
| ours       | Flood  | flood_bots_tcp_2    |   3504 |
| ours       | Flood  | flood_bots_tcp_3    |   3514 |
| ours       | Flood  | flood_bots_udp_1    |   4575 |
| ours       | Flood  | flood_icmp          |   1863 |
| ours       | Flood  | flood_lab           |   2982 |
| ours       | Flood  | flood_pshack        |   1834 |
| ours       | Flood  | flood_rstfin        |   1873 |
| ours       | Flood  | flood_syn           |   3523 |
| ours       | Flood  | flood_syn_slow      |    409 |
| ours       | Flood  | flood_udp           |   1805 |
| ours       | Recon  | recon_connect       |     29 |
| ours       | Recon  | recon_lab           |     92 |
| ours       | Recon  | recon_os            |     19 |
| ours       | Recon  | recon_syn           |     24 |
| ours       | Recon  | recon_version       |      5 |

</details>

### validation.csv  (202,754 rows)

| source     |   Benign |   Flood |   Recon |   total |
|:-----------|---------:|--------:|--------:|--------:|
| CICIoT2023 |     5504 |  188235 |    1098 |  194837 |
| ours       |      581 |    7300 |      36 |    7917 |
| total      |     6085 |  195535 |    1134 |  202754 |

<details><summary>rows per original label / recording</summary>

| source     | y      | label               |   rows |
|:-----------|:-------|:--------------------|-------:|
| CICIoT2023 | Benign | BenignTraffic       |   5504 |
| CICIoT2023 | Flood  | DDoS-ICMP_Flood     |  36402 |
| CICIoT2023 | Flood  | DDoS-PSHACK_Flood   |  20597 |
| CICIoT2023 | Flood  | DDoS-RSTFINFlood    |  20313 |
| CICIoT2023 | Flood  | DDoS-SYN_Flood      |  20529 |
| CICIoT2023 | Flood  | DDoS-TCP_Flood      |  22778 |
| CICIoT2023 | Flood  | DDoS-UDP_Flood      |  27293 |
| CICIoT2023 | Flood  | DoS-SYN_Flood       |  10223 |
| CICIoT2023 | Flood  | DoS-TCP_Flood       |  13411 |
| CICIoT2023 | Flood  | DoS-UDP_Flood       |  16689 |
| CICIoT2023 | Recon  | Recon-OSScan        |    500 |
| CICIoT2023 | Recon  | Recon-PortScan      |    417 |
| CICIoT2023 | Recon  | VulnerabilityScan   |    181 |
| ours       | Benign | benign              |    174 |
| ours       | Benign | benign_plain        |    225 |
| ours       | Benign | flood_ack           |      2 |
| ours       | Benign | flood_icmp          |      2 |
| ours       | Benign | flood_lab           |     84 |
| ours       | Benign | flood_pshack        |      4 |
| ours       | Benign | flood_rstfin        |      6 |
| ours       | Benign | flood_syn           |      5 |
| ours       | Benign | flood_syn_slow      |      3 |
| ours       | Benign | flood_udp           |      4 |
| ours       | Benign | recon_connect       |      6 |
| ours       | Benign | recon_lab           |     51 |
| ours       | Benign | recon_os            |      2 |
| ours       | Benign | recon_ping          |      5 |
| ours       | Benign | recon_syn           |      2 |
| ours       | Benign | recon_version       |      4 |
| ours       | Benign | recon_vuln          |      2 |
| ours       | Flood  | flood_ack           |    410 |
| ours       | Flood  | flood_bots_lab_tcp1 |    110 |
| ours       | Flood  | flood_bots_lab_tcp2 |    117 |
| ours       | Flood  | flood_bots_lab_tcp3 |    140 |
| ours       | Flood  | flood_bots_lab_udp1 |    138 |
| ours       | Flood  | flood_bots_tcp_1    |    748 |
| ours       | Flood  | flood_bots_tcp_2    |    797 |
| ours       | Flood  | flood_bots_tcp_3    |    772 |
| ours       | Flood  | flood_bots_udp_1    |    984 |
| ours       | Flood  | flood_icmp          |    382 |
| ours       | Flood  | flood_lab           |    673 |
| ours       | Flood  | flood_pshack        |    409 |
| ours       | Flood  | flood_rstfin        |    390 |
| ours       | Flood  | flood_syn           |    742 |
| ours       | Flood  | flood_syn_slow      |     85 |
| ours       | Flood  | flood_udp           |    403 |
| ours       | Recon  | recon_connect       |      8 |
| ours       | Recon  | recon_lab           |     20 |
| ours       | Recon  | recon_os            |      3 |
| ours       | Recon  | recon_syn           |      2 |
| ours       | Recon  | recon_version       |      3 |

</details>

### test_dataset.csv  (973,829 rows)

| source     |   Benign |   Flood |   Recon |   total |
|:-----------|---------:|--------:|--------:|--------:|
| CICIoT2023 |    27709 |  940692 |    5428 |  973829 |
| total      |    27709 |  940692 |    5428 |  973829 |

<details><summary>rows per original label / recording</summary>

| source     | y      | label             |   rows |
|:-----------|:-------|:------------------|-------:|
| CICIoT2023 | Benign | BenignTraffic     |  27709 |
| CICIoT2023 | Flood  | DDoS-ICMP_Flood   | 180447 |
| CICIoT2023 | Flood  | DDoS-PSHACK_Flood | 103326 |
| CICIoT2023 | Flood  | DDoS-RSTFINFlood  | 101819 |
| CICIoT2023 | Flood  | DDoS-SYN_Flood    | 102208 |
| CICIoT2023 | Flood  | DDoS-TCP_Flood    | 113735 |
| CICIoT2023 | Flood  | DDoS-UDP_Flood    | 136717 |
| CICIoT2023 | Flood  | DoS-SYN_Flood     |  51116 |
| CICIoT2023 | Flood  | DoS-TCP_Flood     |  67697 |
| CICIoT2023 | Flood  | DoS-UDP_Flood     |  83627 |
| CICIoT2023 | Recon  | Recon-OSScan      |   2433 |
| CICIoT2023 | Recon  | Recon-PortScan    |   2082 |
| CICIoT2023 | Recon  | VulnerabilityScan |    913 |

</details>

### test_ours.csv  (7,671 rows)

| source   |   Benign |   Flood |   Recon |   total |
|:---------|---------:|--------:|--------:|--------:|
| ours     |      567 |    7065 |      39 |    7671 |
| total    |      567 |    7065 |      39 |    7671 |

<details><summary>rows per original label / recording</summary>

| source   | y      | label               |   rows |
|:---------|:-------|:--------------------|-------:|
| ours     | Benign | benign              |    156 |
| ours     | Benign | benign_plain        |    248 |
| ours     | Benign | flood_ack           |      3 |
| ours     | Benign | flood_icmp          |      2 |
| ours     | Benign | flood_lab           |     67 |
| ours     | Benign | flood_pshack        |      1 |
| ours     | Benign | flood_rstfin        |      2 |
| ours     | Benign | flood_syn_slow      |      4 |
| ours     | Benign | flood_udp           |      3 |
| ours     | Benign | recon_connect       |      3 |
| ours     | Benign | recon_lab           |     63 |
| ours     | Benign | recon_os            |      3 |
| ours     | Benign | recon_ping          |      5 |
| ours     | Benign | recon_syn           |      1 |
| ours     | Benign | recon_version       |      1 |
| ours     | Benign | recon_vuln          |      5 |
| ours     | Flood  | flood_ack           |    383 |
| ours     | Flood  | flood_bots_lab_tcp1 |     98 |
| ours     | Flood  | flood_bots_lab_tcp2 |    108 |
| ours     | Flood  | flood_bots_lab_tcp3 |    143 |
| ours     | Flood  | flood_bots_lab_udp1 |    118 |
| ours     | Flood  | flood_bots_tcp_1    |    743 |
| ours     | Flood  | flood_bots_tcp_2    |    725 |
| ours     | Flood  | flood_bots_tcp_3    |    733 |
| ours     | Flood  | flood_bots_udp_1    |    964 |
| ours     | Flood  | flood_icmp          |    405 |
| ours     | Flood  | flood_lab           |    613 |
| ours     | Flood  | flood_pshack        |    382 |
| ours     | Flood  | flood_rstfin        |    437 |
| ours     | Flood  | flood_syn           |    731 |
| ours     | Flood  | flood_syn_slow      |     89 |
| ours     | Flood  | flood_udp           |    393 |
| ours     | Recon  | recon_connect       |      6 |
| ours     | Recon  | recon_lab           |     23 |
| ours     | Recon  | recon_os            |      7 |
| ours     | Recon  | recon_version       |      2 |
| ours     | Recon  | recon_vuln          |      1 |

</details>
