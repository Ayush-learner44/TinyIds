# TinyIDS: the ML part, in one folder

TinyIDS is an intrusion detector that runs on a Raspberry Pi 4. Every 10 packets it computes 14 numbers (packet
sizes, TCP flags, protocol) and one small **LightGBM** model says **Benign**, **Flood** or **Recon** (scan).
If it says attack, the Pi blocks the sender and shows the top-3 reasons (SHAP) on a dashboard.

## Read in this order

| # | Open | What you learn |
|---|---|---|
| 0 | `TinyIDS_ML_Explained.pdf` | **The easy read (12 pages):** everything below in one document, with the pictures |
| 1 | `data_and_model_questions.md` | **Start here.** What data, why only these 3 classes and 14 features, what was removed and why, how it was trained, pruned / not quantized, where everything is |
| 2 | `../train_model14.ipynb` | **The training code**, step by step with explanations. Rebuilds exactly the model on the Pi |
| 3 | `dataset/` (+ its `README.md`) | **The exact rows** the model was trained and tested on (csv) |
| 4 | `model/` | **The model** that runs on the Pi: `model.txt` (LightGBM trees) + `meta.json` (feature list, classes) |
| 5 | `REPORT.md` + `images/` | **The results**: confusion matrices, precision / recall / F1, ROC curve, every one of the 34 attack types, speed and size on the Pi, feature importance |
| 6 | `evaluate.py` | The code that made `REPORT.md` and the pictures |

## The results in 5 lines

- **Attack or not:** F1 **0.997**, detects **99.4%** of attacks, **0.97%** false alarms (dataset test rows).
- **Floods:** 99.7% caught, every flood type 99.1-99.9%.
- **Recon (scans):** the weak class on the dataset (29% caught); in the real lab, our nmap scans were caught
  (plus a port-scan rule).
- **Our own sensors:** 0 false alarms in 564 normal rows (last 15% of every recording, time split); 0 false
  alarms in the final live lab run.
- **On the Pi:** 974 KB model, ~1 ms per decision, SHAP reasons in ~5-14 ms, 77-78 MB RAM.

## Words you will see

- **Precision:** when the model says "Flood", how often it really is one.
- **Recall (detection rate):** of all real floods, how many the model caught.
- **F1:** precision and recall in one number (1.0 = perfect).
- **Macro-F1:** the plain average of the 3 classes' F1 (each class counts the same, so weak Recon pulls it down).
- **Confusion matrix:** rows = the truth, columns = what the model said; the diagonal is correct.
- **SHAP:** for one alert, how much each feature pushed the model towards "attack" (the "reasons" on the dashboard).

## Re-running things

From the `retrain/` folder, with the dataset parquet files in `../project/model/cache/`:
- `train_model14.ipynb`: run all cells (~1-2 min). Writes its model to `notebook_output/` (does not touch the Pi
  model) and checks it is identical; re-exports `dataset/`.
- `cd evaluation_matrices && python evaluate.py` (~2 min): rewrites `REPORT.md` and `images/`.
  (`REPORT.md` sections E and F are about the research question on feature count; ignore them for the basics.)
