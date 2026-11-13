"""Train the two models the live IDS uses and export them to pi/models/ (the live models of the Pi and the Docker testbed).

  binary.txt  : attack or normal
  family.txt  : which family (7 classes: DDoS and DoS merged into "Flood")
  meta.json   : feature list (order matters), classes, window sizes, scores

Only LIVE_FEATURES are used: features the IDS can compute from live packets with a clear meaning.
Left out on purpose: IAT (dataset shortcut), Duration (= TTL, depends on the sender's operating system),
Number / Weight / Variance (encode the dataset's window size), the *_count running totals and Tot sum
(definition not published), Srate / Drate (duplicate or empty), Magnitue / Radius / Covariance (in/out split
not reproducible per source).

Run: python make_ids_models.py            (20% stratified training sample, about 3-5 minutes)
"""
import json
import time
from datetime import date
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, classification_report

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "pi" / "models"
OUT.mkdir(parents=True, exist_ok=True)

LIVE_FEATURES = [
    "flow_duration", "Header_Length", "Protocol Type", "Rate",
    "fin_flag_number", "syn_flag_number", "rst_flag_number", "psh_flag_number",
    "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
    "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC",
    "Min", "Max", "AVG", "Std", "Tot size",
]
WEB = {"SqlInjection", "CommandInjection", "XSS", "BrowserHijacking", "Backdoor_Malware", "Uploading_Attack"}


def family7(l):
    if l == "BenignTraffic": return "Benign"
    if l.startswith("DDoS") or l.startswith("DoS"): return "Flood"
    if l.startswith("Mirai"): return "Mirai"
    if l.startswith("Recon") or l == "VulnerabilityScan": return "Recon"
    if l in ("MITM-ArpSpoofing", "DNS_Spoofing"): return "Spoofing"
    if l in WEB: return "Web"
    return "BruteForce"


def sample(df, frac, seed):
    rng = np.random.default_rng(seed)
    keep = [rng.choice(i, max(1, int(round(len(i) * frac))), replace=False)
            for i in df.groupby("label", observed=True).indices.values()]
    return df.iloc[np.sort(np.concatenate(keep))].reset_index(drop=True)


t0 = time.time()
tr = sample(pd.read_parquet(HERE / "cache" / "train.parquet"), 0.2, 0)
va = sample(pd.read_parquet(HERE / "cache" / "validation.parquet"), 0.2, 1)
te = pd.read_parquet(HERE / "cache" / "test.parquet")
X = {k: d[LIVE_FEATURES].to_numpy(np.float32) for k, d in (("tr", tr), ("va", va), ("te", te))}
print(f"train {len(tr):,} | val {len(va):,} | test {len(te):,} rows, {len(LIVE_FEATURES)} live features")

meta = {"features": LIVE_FEATURES, "trained": str(date.today()), "train_rows": len(tr),
        "windows": {"Flood": 100, "Mirai": 100, "Benign": 10, "Recon": 10, "Spoofing": 10, "Web": 10, "BruteForce": 10}}

for name, labeler in (("binary", lambda s: np.where(s == "BenignTraffic", "Benign", "Attack")),
                      ("family", lambda s: s.map(family7).to_numpy())):
    y_s = {k: labeler(d["label"]) for k, d in (("tr", tr), ("va", va), ("te", te))}
    classes = sorted(set(y_s["tr"]))
    cid = {c: i for i, c in enumerate(classes)}
    y = {k: np.array([cid[c] for c in v]) for k, v in y_s.items()}
    K = len(classes)
    cnt = np.bincount(y["tr"], minlength=K)
    w = (len(y["tr"]) / (K * cnt)) ** 0.5
    w = w / w[y["tr"]].mean()
    m = lgb.LGBMClassifier(objective="binary" if K == 2 else "multiclass", n_estimators=300, learning_rate=0.1,
                           num_leaves=31, max_bin=63, subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                           n_jobs=-1, verbose=-1, random_state=0)
    m.fit(X["tr"], y["tr"], sample_weight=w[y["tr"]], eval_set=[(X["va"], y["va"])],
          callbacks=[lgb.early_stopping(20, verbose=False)])
    m.booster_.save_model(str(OUT / f"{name}.txt"), num_iteration=m.best_iteration_)
    pred = m.predict(X["te"])
    acc, mf1 = accuracy_score(y["te"], pred), f1_score(y["te"], pred, average="macro")
    size = (OUT / f"{name}.txt").stat().st_size / 1024
    print(f"\n=== {name}: {K} classes, {m.best_iteration_} rounds, {size:.0f} KB | test accuracy {acc:.4f}, macro-F1 {mf1:.4f}")
    print(classification_report(y["te"], pred, target_names=classes, digits=3, zero_division=0))
    meta[name] = {"file": f"{name}.txt", "classes": classes, "test_accuracy": round(acc, 4),
                  "test_macro_f1": round(mf1, 4), "size_kb": round(size, 1)}

json.dump(meta, open(OUT / "meta.json", "w"), indent=2)
print(f"saved to {OUT}  ({time.time() - t0:.0f} s)")
