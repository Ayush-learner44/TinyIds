"""Make the two live models SMALL (< 1 MB each) and check how much accuracy that costs.

Why the old family model was 7 MB: 7 classes x ~300 rounds = ~2,100 trees with 31 leaves each.
The size of a LightGBM file grows with (number of trees) x (leaves per tree). So we try smaller trees
(fewer leaves) and keep only as many rounds as fit in 1 MB, then pick the setting with the best
validation macro-F1. Same 30 live features, same classes, same file format: the IDS code does not change.

Run: python make_small_models.py        (needs cache/*.parquet, about 5 minutes on CPU; LightGBM does not use the GPU here)
Output: ../pi/models_small/ (binary.txt, family.txt, meta.json, report.txt)
"""
import json
import time
from datetime import date
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, f1_score

# ---- same features, same 7 families and same sampling as make_ids_models.py
# (copied, not imported: importing make_ids_models.py would run its whole training)
LIVE_FEATURES = [
    "flow_duration", "Header_Length", "Protocol Type", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Min", "Max", "AVG", "Std", "Tot size",
]
WEB = {"SqlInjection", "CommandInjection", "XSS", "BrowserHijacking", "Backdoor_Malware", "Uploading_Attack"}


def family7(label):
    if label == "BenignTraffic": return "Benign"
    if label.startswith("DDoS") or label.startswith("DoS"): return "Flood"
    if label.startswith("Mirai"): return "Mirai"
    if label.startswith("Recon") or label == "VulnerabilityScan": return "Recon"
    if label in ("MITM-ArpSpoofing", "DNS_Spoofing"): return "Spoofing"
    if label in WEB: return "Web"
    return "BruteForce"


def sample(df, frac, seed):
    """Stratified sample: the same fraction of every label."""
    rng = np.random.default_rng(seed)
    keep = [rng.choice(i, max(1, int(round(len(i) * frac))), replace=False)
            for i in df.groupby("label", observed=True).indices.values()]
    return df.iloc[np.sort(np.concatenate(keep))].reset_index(drop=True)

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "pi" / "models_small"     # NOT live yet: worse than the big model on our live bot traffic
OUT.mkdir(parents=True, exist_ok=True)
MAX_BYTES = 1_000_000                     # "< 1 MB"
SETTINGS_TO_TRY = [(7, 0.1), (7, 0.2), (7, 0.3), (15, 0.1), (15, 0.2), (15, 0.3), (31, 0.1)]   # (leaves, learning rate)


def file_size(booster, rounds):
    return len(booster.model_to_string(num_iteration=rounds).encode())


def biggest_rounds_that_fit(booster):
    """The largest number of rounds whose saved file is still under MAX_BYTES."""
    best = 0
    for rounds in range(1, booster.current_iteration() + 1):
        if file_size(booster, rounds) >= MAX_BYTES:
            break
        best = rounds
    return best


def predict(booster, X, rounds):
    p = booster.predict(X, num_iteration=rounds)
    return (p > 0.5).astype(int) if p.ndim == 1 else p.argmax(1)


t0 = time.time()
tr = sample(pd.read_parquet(HERE / "cache" / "train.parquet"), 0.2, 0)
va = sample(pd.read_parquet(HERE / "cache" / "validation.parquet"), 0.2, 1)
te = pd.read_parquet(HERE / "cache" / "test.parquet")
X = {k: d[LIVE_FEATURES].to_numpy(np.float32) for k, d in (("tr", tr), ("va", va), ("te", te))}
print(f"train {len(tr):,} | val {len(va):,} | test {len(te):,} rows")

report = []
meta = {"features": LIVE_FEATURES, "trained": str(date.today()), "train_rows": len(tr),
        "windows": {"Flood": 100, "Mirai": 100, "Benign": 10, "Recon": 10, "Spoofing": 10, "Web": 10, "BruteForce": 10}}

for name, labeler in (("binary", lambda s: np.where(s == "BenignTraffic", "Benign", "Attack")),
                      ("family", lambda s: s.map(family7).to_numpy())):
    y_s = {k: labeler(d["label"]) for k, d in (("tr", tr), ("va", va), ("te", te))}
    classes = sorted(set(y_s["tr"]))
    y = {k: np.array([classes.index(c) for c in v]) for k, v in y_s.items()}
    K = len(classes)
    cnt = np.bincount(y["tr"], minlength=K)
    w = (len(y["tr"]) / (K * cnt)) ** 0.5                     # same class weights as make_ids_models.py
    w = w / w[y["tr"]].mean()

    tried = []
    for leaves, rate in SETTINGS_TO_TRY:
        params = {"objective": "binary" if K == 2 else "multiclass", "num_class": 1 if K == 2 else K,
                  "learning_rate": rate, "num_leaves": leaves, "max_bin": 63, "bagging_fraction": 0.8,
                  "bagging_freq": 1, "feature_fraction": 0.8, "verbose": -1, "seed": 0, "num_threads": 0}
        booster = lgb.train(params, lgb.Dataset(X["tr"], y["tr"], weight=w[y["tr"]]), num_boost_round=300,
                            valid_sets=[lgb.Dataset(X["va"], y["va"])],
                            callbacks=[lgb.early_stopping(20, verbose=False)])
        rounds = min(biggest_rounds_that_fit(booster), booster.best_iteration or booster.current_iteration())
        val_f1 = f1_score(y["va"], predict(booster, X["va"], rounds), average="macro")
        kb = file_size(booster, rounds) / 1024
        line = f"{name}: {leaves:>2} leaves, rate {rate}, {rounds:>3} rounds -> {kb:6.0f} KB, validation macro-F1 {val_f1:.4f}"
        print(line, flush=True)
        report.append(line)
        tried.append((val_f1, leaves, rate, rounds, booster))

    val_f1, leaves, rate, rounds, booster = max(tried, key=lambda t: t[0])
    booster.save_model(str(OUT / f"{name}.txt"), num_iteration=rounds)
    pred = predict(booster, X["te"], rounds)
    acc, mf1 = accuracy_score(y["te"], pred), f1_score(y["te"], pred, average="macro")
    kb = (OUT / f"{name}.txt").stat().st_size / 1024
    line = f"=== {name} CHOSEN: {leaves} leaves, rate {rate}, {rounds} rounds, {kb:.0f} KB | test accuracy {acc:.4f}, macro-F1 {mf1:.4f}"
    print(line)
    report += [line, classification_report(y["te"], pred, target_names=classes, digits=3, zero_division=0)]
    print(report[-1], flush=True)
    meta[name] = {"file": f"{name}.txt", "classes": classes, "test_accuracy": round(acc, 4),
                  "test_macro_f1": round(mf1, 4), "size_kb": round(kb, 1), "num_leaves": leaves, "learning_rate": rate, "rounds": rounds}

json.dump(meta, open(OUT / "meta.json", "w"), indent=2)
(OUT / "report.txt").write_text("\n".join(report))
print(f"saved to {OUT}  ({time.time() - t0:.0f} s)")
