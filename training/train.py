"""Step 4: train ONE small LightGBM (Benign / Flood / Recon) on the dataset + our own recorded rows.

A changed copy of model/make_small_models.py (the original is not touched). What is different:
- 3 classes: Benign / Flood / Recon. Kept dataset attacks: SYN, UDP, ICMP, TCP, PSH-ACK, RST-FIN floods (DoS + DDoS)
  and 3 Recon attacks (port scan, OS scan, vulnerability scan). Dropped: Web, Mirai, HTTP flood, SlowLoris,
  SynonymousIP, fragmentation, ping sweep, host discovery, brute force, spoofing (rules handle the last two).
- Only the 14 features that are computed the same way in the dataset and on the gateway (dataset.md section 3).
- Our own rows from retrain/data/*.csv (recorded with retrain/pi/record.py) are added. Labels:
  benign*.csv -> all Benign; flood_*.csv / recon_*.csv -> rows from the attacker IP = Flood / Recon, the rest Benign;
  flood_bots_*.csv (recorded only while the 10 sensors flooded) -> all Flood.
- Mini RQ1: rank the 14 features (LightGBM gain + mean |SHAP|), then train with the top 5 / 7 / 10 / 14 and compare.

Run:    python train.py            (from retrain/training/; needs ../../model/cache/*.parquet; reads only, writes only in retrain/)
Output: pi/models/top5, top7, top10, top14   (model.txt + meta.json each)   and   train_report.txt
"""
import json
import time
from datetime import date
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score

HERE = Path(__file__).resolve().parent
CACHE = HERE.parent.parent / "model" / "cache"           # the dataset (read only)
if not CACHE.exists():                                    # the v5 copy sits next to the old project folder
    CACHE = HERE.parent.parent / "project" / "model" / "cache"
OUR_DATA = HERE / "data"                          # our recorded rows
OUT = HERE.parent / "pi" / "models"
ATTACKER_IPS = {"172.28.60.66",                   # the attacker in the recording testbed (retrain/testbed)
                "172.29.2.52"}                    # the laptop in the lab, 17 Nov (flood_lab.csv / recon_lab.csv)

FEATURES = ["Protocol Type", "Tot size", "Min", "Max", "AVG", "Std",
            "syn_flag_number", "ack_flag_number", "psh_flag_number", "rst_flag_number", "fin_flag_number",
            "TCP", "UDP", "ICMP"]
CLASSES = ["Benign", "Flood", "Recon"]
FLOODS = {"DDoS-SYN_Flood", "DDoS-UDP_Flood", "DDoS-ICMP_Flood", "DDoS-TCP_Flood", "DDoS-PSHACK_Flood",
          "DDoS-RSTFINFlood", "DoS-SYN_Flood", "DoS-UDP_Flood", "DoS-TCP_Flood"}
RECON = {"Recon-PortScan", "Recon-OSScan", "VulnerabilityScan"}   # ping sweep / host discovery dropped (16 Nov):
                                                                   # < 10 packets to the Pi -> never a full window
MAX_BYTES = 1_000_000                             # "< 1 MB"
THRESHOLD = 0.70                                  # same as the detector: P(attack) below this = normal


def dataset_class(label):
    if label == "BenignTraffic": return "Benign"
    if label in FLOODS: return "Flood"
    if label in RECON: return "Recon"
    return None                                   # not used


def load_dataset(split, fraction, seed):
    """Rows of the kept attacks; a stratified sample (the same fraction of every attack)."""
    df = pd.read_parquet(CACHE / f"{split}.parquet", columns=FEATURES + ["label"])
    df["y"] = df["label"].map(dataset_class)
    df = df[df["y"].notna()]
    if fraction < 1:
        df = df.groupby("label", observed=True, group_keys=False).sample(frac=fraction, random_state=seed)
    return df[FEATURES + ["y"]].reset_index(drop=True)


def load_ours():
    """Our recorded rows, labelled by file name and sender IP; split 70 / 15 / 15 (train / validation / test)."""
    parts = []
    for f in sorted(OUR_DATA.glob("*.csv")):
        d = pd.read_csv(f)
        if "_lab" in f.stem and "pps" in d:          # real lab attacks: drop the laptop's SLOW windows (SSH, stray
            d = d[~(d["src"].isin(ATTACKER_IPS) & (d["pps"] < 20))]   # packets), keep only real attack traffic
        kind = "Flood" if f.name.startswith("flood_") else "Recon" if f.name.startswith("recon_") else "Benign"
        if f.name.startswith("flood_bots"):
            d = d[~d["src"].isin(ATTACKER_IPS)].copy()   # lab files: the laptop's few SSH rows are not bot traffic
            d["y"] = "Flood"                      # recorded only WHILE all the sensors flooded: every sender is a bot
        else:
            d["y"] = np.where(d["src"].isin(ATTACKER_IPS), kind, "Benign")
        d["file"] = f.stem
        parts.append(d)
    ours = pd.concat(parts, ignore_index=True)
    split = np.random.default_rng(0).choice(["tr", "va", "te"], size=len(ours), p=[0.7, 0.15, 0.15])
    return {k: ours[split == k].reset_index(drop=True) for k in ("tr", "va", "te")}


def file_size(booster, rounds):
    return len(booster.model_to_string(num_iteration=rounds).encode())


def train(features, data):
    """One 3-class LightGBM on these features, < 1 MB. Returns (booster, rounds)."""
    X = {k: d[features].to_numpy(np.float32) for k, d in data.items()}
    y = {k: d["y"].map(CLASSES.index).to_numpy() for k, d in data.items()}
    count = np.bincount(y["tr"], minlength=3)
    w = (len(y["tr"]) / (3 * count)) ** 0.5                   # class weights (same idea as make_ids_models.py)
    w = w / w[y["tr"]].mean()
    params = {"objective": "multiclass", "num_class": 3, "learning_rate": 0.1, "num_leaves": 15, "max_bin": 63,
              "bagging_fraction": 0.8, "bagging_freq": 1, "feature_fraction": 0.8, "verbose": -1, "seed": 0}
    booster = lgb.train(params, lgb.Dataset(X["tr"], y["tr"], weight=w[y["tr"]]), num_boost_round=300,
                        valid_sets=[lgb.Dataset(X["va"], y["va"])], callbacks=[lgb.early_stopping(20, verbose=False)])
    rounds = booster.best_iteration or booster.current_iteration()
    while rounds > 1 and file_size(booster, rounds) >= MAX_BYTES:
        rounds -= 1
    return booster, rounds


def decide(booster, X, rounds):
    """The detector's decision: P(attack) = 1 - P(Benign) < 0.70 -> Benign, else the most likely attack class."""
    p = booster.predict(X, num_iteration=rounds)
    attack = 1 + p[:, 1:].argmax(1)
    return np.where(1 - p[:, 0] < THRESHOLD, 0, attack)


def score(booster, rounds, features, d):
    y = d["y"].map(CLASSES.index).to_numpy()
    pred = decide(booster, d[features].to_numpy(np.float32), rounds)
    return y, pred, f1_score(y, pred, average="macro", labels=[0, 1, 2], zero_division=0)


t0 = time.time()
ours = load_ours()
data = {"tr": pd.concat([load_dataset("train", 0.2, 0), ours["tr"]], ignore_index=True),
        "va": pd.concat([load_dataset("validation", 0.2, 1), ours["va"]], ignore_index=True)}
dataset_test = load_dataset("test", 1.0, 2)
report = [f"trained {date.today()}",
          f"train {len(data['tr']):,} rows (ours {len(ours['tr']):,}) | validation {len(data['va']):,} | "
          f"dataset test {len(dataset_test):,} | our test {len(ours['te']):,}",
          "our rows per class: " + str(pd.concat(ours.values())["y"].value_counts().to_dict())]
print("\n".join(report), flush=True)

# ---- 1. rank the 14 features with the full model (gain + mean |SHAP|)
booster, rounds = train(FEATURES, data)
gain = booster.feature_importance("gain", iteration=rounds)
sample_rows = data["va"].sample(min(20000, len(data["va"])), random_state=0)[FEATURES].to_numpy(np.float32)
shap = np.abs(booster.predict(sample_rows, pred_contrib=True, num_iteration=rounds).reshape(len(sample_rows), 3, -1))
shap = shap[:, :, :-1].sum(1).mean(0)                       # mean |SHAP| per feature, summed over the 3 classes
ranking = sorted(FEATURES, key=lambda f: -shap[FEATURES.index(f)])
report.append("\nFeature ranking (mean |SHAP|, gain):")
report += [f"  {i + 1:2d}. {f:<16} SHAP {shap[FEATURES.index(f)]:.3f}   gain {gain[FEATURES.index(f)]:,.0f}"
           for i, f in enumerate(ranking)]
print("\n".join(report[-len(FEATURES) - 1:]), flush=True)

# ---- 2. mini RQ1: top 5 / 7 / 10 / 14 features
report.append("\nk  | dataset test macro-F1 | our test macro-F1 | our benign rows flagged | size KB")
for k in (5, 7, 10, 14):
    features = ranking[:k]
    booster, rounds = train(features, data)
    _, _, f1_dataset = score(booster, rounds, features, dataset_test)
    y_ours, pred_ours, f1_ours = score(booster, rounds, features, ours["te"])
    benign = y_ours == 0
    flagged = int((pred_ours[benign] != 0).sum())
    folder = OUT / f"top{k}"
    folder.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(folder / "model.txt"), num_iteration=rounds)
    kb = (folder / "model.txt").stat().st_size / 1024
    json.dump({"features": features, "trained": str(date.today()),
               "model": {"file": "model.txt", "classes": CLASSES, "rounds": rounds, "size_kb": round(kb, 1),
                         "dataset_test_macro_f1": round(f1_dataset, 4), "our_test_macro_f1": round(f1_ours, 4)}},
              open(folder / "meta.json", "w"), indent=2)
    line = (f"{k:<3}| {f1_dataset:.4f}                | {f1_ours:.4f}            | "
            f"{flagged} of {int(benign.sum())}                | {kb:.0f}")
    report += [line, "  features: " + ", ".join(features),
               "  our test rows:\n" + classification_report(y_ours, pred_ours, labels=[0, 1, 2], target_names=CLASSES,
                                                             digits=3, zero_division=0)]
    print("\n".join(report[-3:]), flush=True)

(HERE / "train_report.txt").write_text("\n".join(report))
print(f"done ({time.time() - t0:.0f} s): models in {OUT}, report in train_report.txt")
