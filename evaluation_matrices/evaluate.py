"""Full evaluation of the live TinyIDS model (and the RQ1 models). Reads only; writes only into this folder.

Run (from retrain/evaluation_matrices):  python evaluate.py          (~3-5 min)
Writes: REPORT.md (all tables) + PNG pictures in images/ (confusion matrices, ROC curve, feature importance, RQ1 plot).

What is evaluated:
 A. the dataset's own test.csv (rows the model never saw), kept classes Benign / Flood / Recon
 B. every one of the dataset's 34 attack types, also the ones we did NOT train on
 C. our own recorded rows (Docker + lab), the 15% held out from training (same split as training/train.py)
 D. size, speed, SHAP time (on this laptop) and feature importance
 E. RQ1: the 5 / 7 / 10 / 14-feature models side by side (the deployed ones)
 F. RQ1 as the proposal asks it: rank all 45 dataset features (46 minus IAT) by SHAP, retrain with the top
    5 / 10 / 15 / 20 / 25 / 30 / 45, compare with "within 2% of all". Offline only, dataset rows only.
"""
import json
import time
from pathlib import Path

import lightgbm as lgb
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
MODELS = ROOT / "pi" / "models"
CACHE = ROOT.parent / "model" / "cache"
if not CACHE.exists():
    CACHE = ROOT.parent / "project" / "model" / "cache"
OUR_DATA = ROOT / "training" / "data"
IMG = HERE / "images"                                     # all pictures go here
IMG.mkdir(exist_ok=True)
ATTACKER_IPS = {"172.28.60.66", "172.29.2.52"}            # same as training/train.py
CLASSES = ["Benign", "Flood", "Recon"]
THRESHOLD = 0.70                                          # same as the live detector
FLOODS = {"DDoS-SYN_Flood", "DDoS-UDP_Flood", "DDoS-ICMP_Flood", "DDoS-TCP_Flood", "DDoS-PSHACK_Flood",
          "DDoS-RSTFINFlood", "DoS-SYN_Flood", "DoS-UDP_Flood", "DoS-TCP_Flood"}
RECON = {"Recon-PortScan", "Recon-OSScan", "VulnerabilityScan"}
report = []


def say(text=""):
    print(text, flush=True)
    report.append(text)


def table(df):
    say(df.to_markdown())
    say()


def load(folder):
    meta = json.load(open(MODELS / folder / "meta.json"))
    return lgb.Booster(model_file=str(MODELS / folder / "model.txt")), meta


def decide(p):
    """The live detector's rule: P(attack) = 1 - P(Benign) < 0.70 -> Benign, else the most likely attack class."""
    return np.where(1 - p[:, 0] < THRESHOLD, 0, 1 + p[:, 1:].argmax(1))


def true_class(label):
    if label == "BenignTraffic": return 0
    if label in FLOODS: return 1
    if label in RECON: return 2
    return -1                                             # an attack type we did not train on


def load_ours_time_split():
    """Our rows split by TIME: in every recording, separately for each class, the first 70% of the rows -> train,
    the next 15% -> validation, the last 15% -> test. (A random row split puts near-identical neighbouring windows
    in train and test, which makes the score too good.) Returns {"tr", "va", "te"}."""
    parts = {"tr": [], "va": [], "te": []}
    for f in sorted(OUR_DATA.glob("*.csv")):
        d = pd.read_csv(f)
        if "_lab" in f.stem and "pps" in d:
            d = d[~(d["src"].isin(ATTACKER_IPS) & (d["pps"] < 20))]
        kind = "Flood" if f.name.startswith("flood_") else "Recon" if f.name.startswith("recon_") else "Benign"
        if f.name.startswith("flood_bots"):
            d = d[~d["src"].isin(ATTACKER_IPS)].copy()
            d["y"] = "Flood"
        else:
            d["y"] = np.where(d["src"].isin(ATTACKER_IPS), kind, "Benign")
        d = d.sort_values("time").reset_index(drop=True)
        d["file"] = f.stem
        for _, g in d.groupby("y"):
            a, b = int(len(g) * 0.70), int(len(g) * 0.85)
            parts["tr"].append(g.iloc[:a])
            parts["va"].append(g.iloc[a:b])
            parts["te"].append(g.iloc[b:])
    return {k: pd.concat(v, ignore_index=True) for k, v in parts.items()}


def train_time_split_model(features, ours_split):
    """Same recipe as training/train.py, but our rows split by time. In memory only, nothing is saved."""
    def dataset_rows(split, seed):
        d = pd.read_parquet(CACHE / f"{split}.parquet", columns=features + ["label"])
        d["y"] = d["label"].astype(str).map(true_class)
        d = d[d["y"] >= 0]
        return d.groupby("label", observed=True, group_keys=False).sample(frac=0.2, random_state=seed)
    tr = pd.concat([dataset_rows("train", 0), ours_split["tr"].assign(y=ours_split["tr"]["y"].map(CLASSES.index))])
    va = pd.concat([dataset_rows("validation", 1), ours_split["va"].assign(y=ours_split["va"]["y"].map(CLASSES.index))])
    ytr = tr["y"].to_numpy().astype(int)
    w = (len(ytr) / (3 * np.bincount(ytr, minlength=3))) ** 0.5
    w = w / w[ytr].mean()
    params = {"objective": "multiclass", "num_class": 3, "learning_rate": 0.1, "num_leaves": 15, "max_bin": 63,
              "bagging_fraction": 0.8, "bagging_freq": 1, "feature_fraction": 0.8, "verbose": -1, "seed": 0}
    return lgb.train(params, lgb.Dataset(tr[features].to_numpy(np.float32), ytr, weight=w[ytr]), num_boost_round=300,
                     valid_sets=[lgb.Dataset(va[features].to_numpy(np.float32), va["y"].to_numpy().astype(int))],
                     callbacks=[lgb.early_stopping(20, verbose=False)])


def load_ours_test():
    """Exactly the split of training/train.py (seed 0): returns the 15% test rows."""
    parts = []
    for f in sorted(OUR_DATA.glob("*.csv")):
        d = pd.read_csv(f)
        if "_lab" in f.stem and "pps" in d:
            d = d[~(d["src"].isin(ATTACKER_IPS) & (d["pps"] < 20))]
        kind = "Flood" if f.name.startswith("flood_") else "Recon" if f.name.startswith("recon_") else "Benign"
        if f.name.startswith("flood_bots"):
            d = d[~d["src"].isin(ATTACKER_IPS)].copy()
            d["y"] = "Flood"
        else:
            d["y"] = np.where(d["src"].isin(ATTACKER_IPS), kind, "Benign")
        d["file"] = f.stem
        parts.append(d)
    ours = pd.concat(parts, ignore_index=True)
    split = np.random.default_rng(0).choice(["tr", "va", "te"], size=len(ours), p=[0.7, 0.15, 0.15])
    return ours[split == "te"].reset_index(drop=True)


def plot_cm(cm, title, name, labels=CLASSES):
    norm = cm / cm.sum(1, keepdims=True).clip(min=1)
    fig, ax = plt.subplots(figsize=(5.2, 4.4))
    ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, f"{cm[i, j]:,}\n{norm[i, j] * 100:.1f}%", ha="center", va="center", fontsize=9,
                    color="white" if norm[i, j] > 0.5 else "black")
    ax.set_xticks(range(len(labels)), labels)
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.set_title(title, fontsize=10)
    fig.tight_layout()
    fig.savefig(IMG / name, dpi=130)
    plt.close(fig)


def per_class_table(y, pred):
    rows = []
    for i, c in enumerate(CLASSES):
        rows.append({"class": c, "rows": int((y == i).sum()),
                     "precision": round(precision_score(y, pred, labels=[i], average="macro", zero_division=0), 4),
                     "recall": round(recall_score(y, pred, labels=[i], average="macro", zero_division=0), 4),
                     "F1": round(f1_score(y, pred, labels=[i], average="macro", zero_division=0), 4)})
    return pd.DataFrame(rows).set_index("class")


def binary_table(y, p_attack, pred):
    """Attack (Flood or Recon) vs Benign: the IDS question 'is this an attack at all?'."""
    yb, pb = (y != 0).astype(int), (pred != 0).astype(int)
    tn, fp, fn, tp = confusion_matrix(yb, pb, labels=[0, 1]).ravel()
    return pd.DataFrame([{
        "accuracy": round(accuracy_score(yb, pb), 4), "precision (attack)": round(tp / max(tp + fp, 1), 4),
        "recall / detection rate": round(tp / max(tp + fn, 1), 4), "F1 (attack)": round(f1_score(yb, pb), 4),
        "macro-F1": round(f1_score(yb, pb, average="macro"), 4),
        "false-positive rate": round(fp / max(fp + tn, 1), 4), "false-negative rate": round(fn / max(fn + tp, 1), 4),
        "ROC-AUC": round(roc_auc_score(yb, p_attack), 4)}]).T.rename(columns={0: "value"})


t0 = time.time()
booster, meta = load("top14")
F = meta["features"]
say("# TinyIDS evaluation (live model `pi/models/top14`)")
say()
say(f"Model: one LightGBM, 3 classes {CLASSES}, {len(F)} features, {(MODELS / 'top14' / 'model.txt').stat().st_size / 1024:.0f} KB. "
    f"Decision rule as on the Pi: P(attack) = 1 - P(Benign) >= {THRESHOLD} -> attack, then the most likely attack class.")
say()

# ---------------------------------------------------------------- A. dataset test.csv, kept classes
test = pd.read_parquet(CACHE / "test.parquet", columns=F + ["label"])
test["label"] = test["label"].astype(str)
test["y"] = test["label"].map(true_class)
kept = test[test["y"] >= 0].reset_index(drop=True)
p = booster.predict(kept[F].to_numpy(np.float32))
pred, y = decide(p), kept["y"].to_numpy()
say("## A. Dataset test rows (CICIoT2023 test.csv, never used in training)")
say()
say(f"{len(kept):,} rows of the kept classes (Benign {int((y == 0).sum()):,}, Flood {int((y == 1).sum()):,}, "
    f"Recon {int((y == 2).sum()):,}).")
say()
say(f"**3-class:** accuracy {accuracy_score(y, pred):.4f}, macro-F1 {f1_score(y, pred, average='macro'):.4f}, "
    f"weighted-F1 {f1_score(y, pred, average='weighted'):.4f}")
say()
table(per_class_table(y, pred))
cm = confusion_matrix(y, pred, labels=[0, 1, 2])
table(pd.DataFrame(cm, index=[f"true {c}" for c in CLASSES], columns=[f"pred {c}" for c in CLASSES]))
plot_cm(cm, "Dataset test rows (CICIoT2023)", "cm_dataset_test.png")
say("Picture: `images/cm_dataset_test.png`")
say()
say("**Binary (attack vs benign):**")
say()
table(binary_table(y, 1 - p[:, 0], pred))
fpr, tpr, _ = roc_curve((y != 0).astype(int), 1 - p[:, 0])

# ---------------------------------------------------------------- B. every attack type
say("## B. Every one of the 34 dataset labels (test.csv)")
say()
say("`detected` = called an attack at all (Flood or Recon). `right family` = Flood for floods, Recon for scans. "
    "Labels marked *not trained* were left out of training on purpose (rules handle them, or they need a web server).")
say()
p_all = booster.predict(test[F].to_numpy(np.float32))
pred_all = decide(p_all)
rows = []
for label, g in test.assign(pred=pred_all).groupby("label"):
    tc = true_class(label)
    rows.append({"label": label, "rows": len(g), "trained on": "yes" if tc >= 0 else "not trained",
                 "detected as attack": round(float((g["pred"] != 0).mean()), 4) if label != "BenignTraffic" else None,
                 "right family": round(float((g["pred"] == tc).mean()), 4) if tc >= 0 else None,
                 "false alarm rate": round(float((g["pred"] != 0).mean()), 4) if label == "BenignTraffic" else None})
table(pd.DataFrame(rows).set_index("label").sort_values(["trained on", "rows"], ascending=[False, False]))

# ---------------------------------------------------------------- C. our own held-out rows
ours_split = load_ours_time_split()
booster_c = train_time_split_model(F, ours_split)
ours = ours_split["te"]
yo = ours["y"].map(CLASSES.index).to_numpy()
po = booster_c.predict(ours[F].to_numpy(np.float32))
predo = decide(po)
say("## C. Our own recorded rows (Docker testbed + real Pi lab), TIME split: the last 15% of every recording")
say()
say(f"{len(ours):,} rows (Benign {int((yo == 0).sum()):,}, Flood {int((yo == 1).sum()):,}, Recon {int((yo == 2).sum()):,}).")
say()
say("**How:** each recording is in time order. For every recording (and separately for its normal and attack rows) "
    "the first 70% of the rows were used for training, the next 15% for validation, and the **last 15%** for this "
    "test. Train and test only touch at one point in time, so the test is close to new data. (A random row split would "
    "put near-identical neighbouring windows in both, which makes the score too good: macro-F1 0.957 instead of the "
    "honest number below.) For this, a model was trained with exactly the same recipe and dataset rows as the "
    f"deployed one, only with our rows split by time ({booster_c.best_iteration or booster_c.current_iteration()} "
    "trees, in memory only). The live lab runs (RESULTS.md) remain the fully independent test.")
say()
say(f"**3-class:** accuracy {accuracy_score(yo, predo):.4f}, macro-F1 {f1_score(yo, predo, average='macro'):.4f}")
say()
table(per_class_table(yo, predo))
cmo = confusion_matrix(yo, predo, labels=[0, 1, 2])
table(pd.DataFrame(cmo, index=[f"true {c}" for c in CLASSES], columns=[f"pred {c}" for c in CLASSES]))
plot_cm(cmo, "Our own recorded rows (last 15% of every recording)", "cm_our_rows.png")
say("Picture: `images/cm_our_rows.png`")
say()
say("**Binary (attack vs benign):**")
say()
table(binary_table(yo, 1 - po[:, 0], predo))
say("**Per recording (test rows only):**")
say()
rows = []
for f, g in ours.assign(pred=predo, yy=yo).groupby("file"):
    rows.append({"recording": f, "rows": len(g), "correct": round(float((g["pred"] == g["yy"]).mean()), 4),
                 "benign rows flagged": int(((g["yy"] == 0) & (g["pred"] != 0)).sum())})
table(pd.DataFrame(rows).set_index("recording"))

# ---------------------------------------------------------------- D. size, speed, importance
say("## D. Size, speed, explanation time, feature importance")
say()
one = kept[F].to_numpy(np.float32)[:2000]
start = time.perf_counter()
for i in range(len(one)):
    booster.predict(one[i:i + 1])
model_ms = (time.perf_counter() - start) * 1000 / len(one)
start = time.perf_counter()
for i in range(200):
    booster.predict(one[i:i + 1], pred_contrib=True)
shap_ms = (time.perf_counter() - start) * 1000 / 200
table(pd.DataFrame([
    {"measure": "model file size", "laptop": f"{(MODELS / 'top14' / 'model.txt').stat().st_size / 1024:.0f} KB",
     "Raspberry Pi (lab, measured live)": "same file", "target": "< 1 MB"},
    {"measure": "prediction time per window", "laptop": f"{model_ms:.2f} ms",
     "Raspberry Pi (lab, measured live)": "~0.7-1.4 ms (dashboard)", "target": "< 5 ms"},
    {"measure": "SHAP time per alert", "laptop": f"{shap_ms:.2f} ms",
     "Raspberry Pi (lab, measured live)": "~5-14 ms (dashboard)", "target": "< 50 ms"},
    {"measure": "RAM of the whole detector", "laptop": "-",
     "Raspberry Pi (lab, measured live)": "77-78 MB", "target": "< 100 MB"}]).set_index("measure"))
gain = booster.feature_importance("gain")
sample = kept.sample(20000, random_state=0)[F].to_numpy(np.float32)
shap = np.abs(booster.predict(sample, pred_contrib=True).reshape(len(sample), 3, -1))[:, :, :-1].sum(1).mean(0)
imp = pd.DataFrame({"feature": F, "mean |SHAP|": shap.round(3), "gain": gain.round(0)}).sort_values(
    "mean |SHAP|", ascending=False).set_index("feature")
table(imp)
fig, ax = plt.subplots(figsize=(6, 4.2))
ax.barh(imp.index[::-1], imp["mean |SHAP|"][::-1], color="#4C72B0")
ax.set_xlabel("mean |SHAP| (how much the feature moves the decision)")
ax.set_title("Feature importance (top14 model)", fontsize=10)
fig.tight_layout()
fig.savefig(IMG / "feature_importance.png", dpi=130)
plt.close(fig)
say("Picture: `images/feature_importance.png`")
say()

# ---------------------------------------------------------------- E. RQ1: 5 / 7 / 10 / 14 features
say("## E. RQ1: how many features? (5 / 7 / 10 / 14, same training, dataset test rows)")
say()
rows, curves = [], []
for k in (5, 7, 10, 14):
    b, m = load(f"top{k}")
    pk = b.predict(kept[m["features"]].to_numpy(np.float32))
    dk = decide(pk)
    po_k = decide(b.predict(ours[m["features"]].to_numpy(np.float32)))
    rows.append({"features": k, "dataset macro-F1": round(f1_score(y, dk, average="macro"), 4),
                 "dataset binary F1 (attack)": round(f1_score((y != 0).astype(int), (dk != 0).astype(int)), 4),
                 "dataset Recon recall": round(recall_score(y, dk, labels=[2], average="macro"), 4),
                 "our rows macro-F1": round(f1_score(yo, po_k, average="macro"), 4),
                 "size KB": round((MODELS / f"top{k}" / "model.txt").stat().st_size / 1024)})
rq1 = pd.DataFrame(rows).set_index("features")
table(rq1)
fig, ax = plt.subplots(figsize=(5.5, 3.8))
ax.plot(rq1.index, rq1["dataset macro-F1"], "o-", label="dataset macro-F1 (3 classes)")
ax.plot(rq1.index, rq1["dataset binary F1 (attack)"], "s-", label="dataset binary F1")
ax.plot(rq1.index, rq1["our rows macro-F1"], "^-", label="our rows macro-F1")
ax.set_xlabel("number of features")
ax.set_ylim(0.5, 1.01)
ax.legend(fontsize=8)
ax.set_title("RQ1: score vs number of features", fontsize=10)
fig.tight_layout()
fig.savefig(IMG / "rq1_features.png", dpi=130)
plt.close(fig)
say("Picture: `images/rq1_features.png`")
say()

# ---------------------------------------------------------------- F. RQ1 as in the proposal: all 45 features, offline
# The proposal's RQ1: "how few of the 46 features keep macro-F1 within 2% of the full-feature model?"
# OFFLINE ONLY (never deployed): most of these features are not computed the same way on the Pi (dataset.md sec. 3),
# so only dataset rows are used here, not our recordings. Same task (Benign / Flood / Recon), same LightGBM settings,
# same 20% training sample and same 0.70 decision rule as training/train.py. IAT is left out (time-stamp shortcut,
# dataset.md sec. 4), so "all" = 45. Ranking = mean |SHAP| of the all-45 model on 3,000 validation rows.
say("## F. RQ1 as in the proposal: top 5 / 10 / 15 / 20 / 25 / 30 / all 45 features (offline, dataset only)")
say()
ALL45 = [c for c in pd.read_parquet(CACHE / "test.parquet").columns if c not in ("label", "IAT")]


def load_all45(split, fraction, seed):
    d = pd.read_parquet(CACHE / f"{split}.parquet", columns=ALL45 + ["label"])
    d["y"] = d["label"].map(true_class)
    d = d[d["y"] >= 0]
    if fraction < 1:
        d = d.groupby("label", observed=True, group_keys=False).sample(frac=fraction, random_state=seed)
    return d.reset_index(drop=True)


def train_offline(features, tr, va):
    """Same LightGBM recipe as training/train.py (no 1 MB cap: this model never goes on the Pi)."""
    ytr = tr["y"].to_numpy()
    w = (len(ytr) / (3 * np.bincount(ytr, minlength=3))) ** 0.5
    w = w / w[ytr].mean()
    params = {"objective": "multiclass", "num_class": 3, "learning_rate": 0.1, "num_leaves": 15, "max_bin": 63,
              "bagging_fraction": 0.8, "bagging_freq": 1, "feature_fraction": 0.8, "verbose": -1, "seed": 0}
    return lgb.train(params, lgb.Dataset(tr[features].to_numpy(np.float32), ytr, weight=w[ytr]),
                     num_boost_round=300,
                     valid_sets=[lgb.Dataset(va[features].to_numpy(np.float32), va["y"].to_numpy())],
                     callbacks=[lgb.early_stopping(20, verbose=False)])


t_f = time.time()
tr45, va45, te45 = load_all45("train", 0.2, 0), load_all45("validation", 0.2, 1), load_all45("test", 1.0, 2)
y45 = te45["y"].to_numpy()
full = train_offline(ALL45, tr45, va45)
contrib = full.predict(va45[ALL45].sample(3000, random_state=0).to_numpy(np.float32), pred_contrib=True)
n = len(ALL45) + 1                                        # per class: 45 SHAP values + 1 bias
shap_mean = np.abs(contrib.reshape(len(contrib), 3, n)[:, :, :-1]).sum(1).mean(0)
ranking = [ALL45[i] for i in np.argsort(-shap_mean)]
rows = []
for k in (5, 10, 15, 20, 25, 30, len(ALL45)):
    feats = ALL45 if k == len(ALL45) else ranking[:k]     # the full model needs its own column order
    b = full if k == len(ALL45) else train_offline(feats, tr45, va45)
    dk = decide(b.predict(te45[feats].to_numpy(np.float32)))
    rows.append({"features": k, "dataset macro-F1": round(f1_score(y45, dk, average="macro"), 4),
                 "dataset binary F1 (attack)": round(f1_score((y45 != 0).astype(int), (dk != 0).astype(int)), 4),
                 "dataset Recon recall": round(recall_score(y45, dk, labels=[2], average="macro"), 4),
                 "size KB": round(len(b.model_to_string().encode()) / 1024),
                 "Pi can compute all": all(f in F for f in feats)})
rq1f = pd.DataFrame(rows).set_index("features")
best = rq1f.loc[len(ALL45), "dataset macro-F1"]
rq1f["within 2% of all-45"] = rq1f["dataset macro-F1"] >= best - 0.02
table(rq1f)
smallest = rq1f.index[rq1f["within 2% of all-45"]].min()
say(f"**Answer (3-class task, dataset):** all 45 features give macro-F1 {best:.4f}; the smallest tested set within "
    f"0.02 of that is **{smallest} features** ({rq1f.loc[smallest, 'dataset macro-F1']:.4f}). For comparison, the "
    f"deployed 14 Pi-computable features give {rq1.loc[14, 'dataset macro-F1']:.4f} (section E; that model is also "
    f"trained on our own rows).")
say()
say("SHAP ranking of all 45 (most important first; **bold** = one of the 14 the Pi computes like the dataset):")
say()
say(", ".join(f"**{f}**" if f in F else f for f in ranking))
say()
fig, ax = plt.subplots(figsize=(5.5, 3.8))
ax.plot(rq1f.index, rq1f["dataset macro-F1"], "o-", label="all-45 ranking: macro-F1")
ax.plot(rq1f.index, rq1f["dataset binary F1 (attack)"], "s-", label="all-45 ranking: binary F1")
ax.axhline(best - 0.02, ls="--", color="grey", lw=0.8, label="2% below all-45")
ax.plot(rq1.index, rq1["dataset macro-F1"], "^:", label="Pi-computable 14 (section E)")
ax.set_xlabel("number of features")
ax.set_ylim(0.5, 1.01)
ax.legend(fontsize=7)
ax.set_title("RQ1 (offline): macro-F1 vs number of features", fontsize=10)
fig.tight_layout()
fig.savefig(IMG / "rq1_all45.png", dpi=130)
plt.close(fig)
say(f"Picture: `images/rq1_all45.png`  (section F took {time.time() - t_f:.0f} s)")
say()

# ROC picture
fig, ax = plt.subplots(figsize=(4.6, 4.2))
ax.plot(fpr, tpr, label=f"dataset test (AUC {roc_auc_score((y != 0).astype(int), 1 - p[:, 0]):.4f})")
fpr_o, tpr_o, _ = roc_curve((yo != 0).astype(int), 1 - po[:, 0])
ax.plot(fpr_o, tpr_o, label=f"our rows (AUC {roc_auc_score((yo != 0).astype(int), 1 - po[:, 0]):.4f})")
ax.plot([0, 1], [0, 1], "--", color="grey", linewidth=0.8)
ax.set_xlabel("false-positive rate")
ax.set_ylabel("true-positive rate (detection rate)")
ax.set_title("ROC: attack vs benign", fontsize=10)
ax.legend(fontsize=8)
fig.tight_layout()
fig.savefig(IMG / "roc_attack_vs_benign.png", dpi=130)
plt.close(fig)
say("ROC picture (A + C): `images/roc_attack_vs_benign.png`")
say()
say(f"_Evaluation took {time.time() - t0:.0f} s._")

# ---------------------------------------------------------------- fixed text: glossary + summary
say("""---

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
- **Size / speed:** 974 KB (< 1 MB), ~1 ms per window and ~5-14 ms SHAP on the Pi, 77-78 MB RAM: all targets met.""")
(HERE / "REPORT.md").write_text("\n".join(report), encoding="utf-8")
