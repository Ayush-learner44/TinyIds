# Fresh training run, 13 Nov 2026 (`model/fresh/train_fresh.py`)

20 % stratified sample of train.csv (1.1 M rows), early stopping on 20 % of validation.csv, scored on the FULL test.csv (1.18 M rows; INT8 rows on 50,000 random test rows scored one row at a time). 45 features (no IAT).
Size = bytes of the saved model. Latency = ONE row at a time on the laptop CPU (Pi is ~3-4x slower).
"old" = macro-F1 of the previous run (results_run2, 3 epochs for the nets).

## binary

| model | version | accuracy | macro-F1 | old macro-F1 | benign false alarms | size (KB) | latency (ms) |
|---|---|---|---|---|---|---|---|
| rf | full | 0.9930 | **0.9322** | 0.9322 | 0.0165 | 7,291.0 | 4.563 |
| rf | edge: 30 trees d12 | 0.9908 | **0.9153** |  | 0.0086 | 904.4 | 1.583 |
| lgbm | full (513 rds) | 0.9942 | **0.9415** | 0.9450 | 0.0377 | 3,404.6 | 0.086 |
| lgbm | edge: <1MB (339 rds) | 0.9933 | **0.9349** |  | 0.0231 | 581.1 | 0.056 |
| mlp | full (fp32) | 0.9924 | **0.9275** | 0.9158 | 0.0191 | 186.6 | 0.129 |
| mlp | edge: INT8 (50k rows) | 0.9918 | **0.9190** |  | 0.0266 | 58.2 | 0.417 |
| cnn | full (fp32) | 0.9933 | **0.9351** | 0.8792 | 0.0198 | 260.9 | 0.266 |
| cnn | edge: INT8 (50k rows) | 0.9929 | **0.9288** |  | 0.0292 | 81.4 | 0.446 |

## 8class

| model | version | accuracy | macro-F1 | old macro-F1 | benign false alarms | size (KB) | latency (ms) |
|---|---|---|---|---|---|---|---|
| rf | full | 0.9051 | **0.6880** | 0.6876 | 0.0808 | 39,438.2 | 4.741 |
| rf | edge: 30 trees d12 | 0.8947 | **0.6662** |  | 0.0969 | 2,904.9 | 1.588 |
| lgbm | full (256 rds) | 0.9082 | **0.7021** | 0.7049 | 0.0832 | 13,719.5 | 0.256 |
| lgbm | edge: <1MB (66 rds) | 0.9014 | **0.6691** |  | 0.1090 | 907.2 | 0.071 |
| mlp | full (fp32) | 0.8965 | **0.6809** | 0.6386 | 0.1034 | 189.6 | 0.106 |
| mlp | edge: INT8 (50k rows) | 0.8975 | **0.6713** |  | 0.1125 | 58.9 | 0.449 |
| cnn | full (fp32) | 0.9038 | **0.6860** | 0.6111 | 0.0892 | 263.9 | 0.251 |
| cnn | edge: INT8 (50k rows) | 0.9065 | **0.6867** |  | 0.1027 | 82.2 | 0.461 |

## 34class

| model | version | accuracy | macro-F1 | old macro-F1 | benign false alarms | size (KB) | latency (ms) |
|---|---|---|---|---|---|---|---|
| rf | full | 0.8874 | **0.6486** | 0.6472 | 0.0717 | 54,634.8 | 4.500 |
| rf | edge: 30 trees d12 | 0.8780 | **0.6082** |  | 0.0750 | 3,617.0 | 1.509 |
| lgbm | full (60 rds) | 0.8880 | **0.6382** | 0.6266 | 0.1204 | 13,618.5 | 0.238 |
| lgbm | edge: <1MB (13 rds) | 0.8766 | **0.5888** |  | 0.1772 | 751.3 | 0.067 |
| mlp | full (fp32) | 0.8809 | **0.6420** | 0.5534 | 0.1293 | 202.7 | 0.123 |
| mlp | edge: INT8 (50k rows) | 0.8809 | **0.6519** |  | 0.1355 | 62.3 | 0.389 |
| cnn | full (fp32) | 0.8706 | **0.6155** | 0.5320 | 0.0987 | 277.0 | 0.237 |
| cnn | edge: INT8 (50k rows) | 0.8718 | **0.6208** |  | 0.0974 | 85.5 | 0.455 |

## Takeaways
- **All four model families end up close** (8-class macro-F1 0.68-0.70, 34-class 0.62-0.65). The limit is the data
  (Web / BruteForce / Spoofing / DoS-vs-DDoS look alike in these features), not the model type.
- **Neural nets improved a lot** with proper training (up to 40 epochs, BatchNorm, learning-rate drops, best epoch kept):
  8-class MLP 0.639 -> 0.681, CNN 0.611 -> 0.686; 34-class MLP 0.553 -> 0.642, CNN 0.532 -> 0.616.
  Trees are unchanged within +-0.01 (34-class LightGBM +0.012 with a gentler learning rate).
- **Edge versions all fit < 1 MB except RF** (8/34-class RF needs 2.9-3.6 MB even with 30 trees of depth 12).
  INT8 nets are 58-86 KB and lose at most ~0.01 macro-F1 against fp32 on the same 50k rows (`fresh_nets.csv`).
- **INT8 is NOT faster on the laptop** for one row at a time (0.39-0.46 ms vs 0.11-0.27 ms fp32): dynamic quantization
  adds work per call; its benefit is size. LightGBM edge is the fastest (0.05-0.07 ms) and the only one with exact,
  fast SHAP -> it stays the deployed model.
- Run on the CPU (CUDA PyTorch download did not finish on this connection); the nets are small, 2-10 min each.
