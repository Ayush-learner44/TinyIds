# %% [markdown]
# # TinyIDS: model training on CICIoT2023
#
# This notebook / script does the **offline** half of TinyIDS (see `notes/TinyIDS_project_explained.pdf`):
#
# 1. Load the **full** CICIoT2023 split from Kaggle (`train.csv` 5.49 M rows, `validation.csv`, `test.csv` 1.18 M rows each).
# 2. Build the three label sets the proposal asks for: **binary** (Benign vs Attack), **8-class** (attack family), **34-class** (exact attack).
# 3. Handle the **class imbalance** (DDoS is 73 % of rows, some web attacks have < 200 rows).
# 4. Train the four models from the proposal: **Random Forest (RF)**, **LightGBM** (Light Gradient Boosting Machine),
#    **MLP** (Multi-Layer Perceptron, a basic neural network) and a small **1D-CNN** (one-dimensional Convolutional Neural Network).
# 5. Score every model on `test.csv`: accuracy, **macro-F1**, per-class recall, benign false-alarm rate, confusion matrix,
#    model size, prediction time.
# 6. **RQ1** (Research Question 1): rank the 46 features with **SHAP** (SHapley Additive exPlanations), retrain with the top
#    **5 / 10 / 15 / 20** features and compare macro-F1 with the all-46 model ("within 2 %").
#
# Everything is saved in `model/results/` (tables, plots) and `model/models/` (trained model files for the Pi).
#
# **Run as a script:** `python train_tinyids.py` (full run, all tasks and models; takes a while)
# **Quick test:** `python train_tinyids.py --sample 0.02 --epochs 1`
# **Only some parts:** `python train_tinyids.py --tasks binary,8class --models lgbm,rf`

# %% [markdown]
# ## 1. Imports and settings
#
# All settings live in `CFG`. When run as a script they come from the command line; in Jupyter the defaults are used
# (edit the `defaults` below to change them).

# %%
import argparse
import json
import os
import sys
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

IN_NOTEBOOK = "ipykernel" in sys.modules
import matplotlib
if not IN_NOTEBOOK:
    matplotlib.use("Agg")          # no windows when run as a script, just save PNG files
import matplotlib.pyplot as plt

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, f1_score, classification_report,
                             confusion_matrix, ConfusionMatrixDisplay)

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", message=".*eval_set.*deprecated.*")   # harmless LightGBM notice

HERE = Path(__file__).resolve().parent if "__file__" in globals() else Path.cwd()

parser = argparse.ArgumentParser(description="Train TinyIDS models on CICIoT2023")
parser.add_argument("--data-dir", default=str(HERE.parent / "dataset" / "archive" / "CICIOT23"))
parser.add_argument("--tasks", default="binary,8class,34class", help="comma list: binary,8class,34class")
parser.add_argument("--models", default="rf,lgbm,mlp,cnn", help="comma list: rf,lgbm,mlp,cnn")
parser.add_argument("--sample", type=float, default=1.0, help="fraction of train.csv to use (1.0 = all 5.49 M rows)")
parser.add_argument("--val-sample", type=float, default=0.2, help="fraction of validation.csv used for early stopping")
parser.add_argument("--test-sample", type=float, default=1.0, help="fraction of test.csv used for scoring")
parser.add_argument("--epochs", type=int, default=3, help="training epochs for MLP / 1D-CNN")
parser.add_argument("--topk", default="5,10,15,20,25,30", help="feature counts for RQ1")
parser.add_argument("--skip-rq1", action="store_true", help="skip the SHAP feature-selection experiment")
parser.add_argument("--drop", default="", help="comma list of features to leave out, e.g. IAT")
parser.add_argument("--lgbm-lr", type=float, default=0.05, help="LightGBM learning rate")
parser.add_argument("--run-name", default="", help="suffix for output folders, e.g. run2 -> results_run2/, models_run2/")
CFG = parser.parse_known_args(args=[] if IN_NOTEBOOK else None)[0]

TASKS = [t.strip() for t in CFG.tasks.split(",") if t.strip()]
MODELS = [m.strip() for m in CFG.models.split(",") if m.strip()]
TOPK = [int(k) for k in CFG.topk.split(",") if k.strip()]
DROP = [f.strip() for f in CFG.drop.split(",") if f.strip()]

SUFFIX = f"_{CFG.run_name}" if CFG.run_name else ""
OUT = HERE / f"results{SUFFIX}"
MODELS_DIR = HERE / f"models{SUFFIX}"
CACHE = HERE / "cache"
for d in (OUT, MODELS_DIR, CACHE):
    d.mkdir(exist_ok=True)

N_CPU = os.cpu_count() or 4
T_START = time.time()


def log(msg):
    """Print with elapsed time, so long runs show progress."""
    m, s = divmod(int(time.time() - T_START), 60)
    print(f"[{m:3d}m{s:02d}s] {msg}", flush=True)


log(f"Config: {vars(CFG)}  |  CPU cores: {N_CPU}")

# %% [markdown]
# ## 2. Load the data
#
# The CSV files are big (train 1.6 GB). The first run reads them and saves a compressed **Parquet** copy in `model/cache/`;
# later runs load the Parquet file in seconds. Features are stored as `float32` (half the memory of the default `float64`).
#
# A few cells in CICIoT2023 contain `inf` (infinity, e.g. a rate divided by a zero duration); they are replaced by 0.

# %%
def load_split(name):
    cache = CACHE / f"{name}.parquet"
    if cache.exists():
        df = pd.read_parquet(cache)
        log(f"{name}: loaded cache {cache.name}  ({len(df):,} rows)")
        return df
    path = Path(CFG.data_dir) / name / f"{name}.csv"
    log(f"{name}: reading {path} (first time only, can take a minute) ...")
    df = pd.read_csv(path, engine="pyarrow")
    df.columns = [c.strip() for c in df.columns]
    feats = [c for c in df.columns if c != "label"]
    df[feats] = df[feats].astype("float32").replace([np.inf, -np.inf], np.nan).fillna(0)
    df["label"] = df["label"].astype(str).str.strip()
    df.to_parquet(cache, index=False)
    log(f"{name}: {len(df):,} rows, saved cache")
    return df


def stratified_sample(df, frac, seed=0):
    """Keep `frac` of the rows of EVERY label (so rare attacks don't disappear)."""
    if frac >= 1.0:
        return df
    rng = np.random.default_rng(seed)
    keep = []
    for _, idx in df.groupby("label", observed=True).indices.items():
        n = max(1, int(round(len(idx) * frac)))
        keep.append(rng.choice(idx, n, replace=False))
    return df.iloc[np.sort(np.concatenate(keep))].reset_index(drop=True)


train_df = stratified_sample(load_split("train"), CFG.sample)
val_df = stratified_sample(load_split("validation"), CFG.val_sample, seed=1)
test_df = stratified_sample(load_split("test"), CFG.test_sample, seed=2)
FEATURES = [c for c in train_df.columns if c != "label" and c not in DROP]
log(f"Using train {len(train_df):,} | val {len(val_df):,} | test {len(test_df):,} rows, {len(FEATURES)} features"
    + (f" (left out: {', '.join(DROP)})" if DROP else ""))

# %% [markdown]
# ## 3. Labels: binary, 8-class, 34-class
#
# The 34 original labels are grouped into the 8 families of the CICIoT2023 paper
# (see `notes/ciciot2023_classes.pdf` for the tree).

# %%
WEB = {"SqlInjection", "CommandInjection", "XSS", "BrowserHijacking", "Backdoor_Malware", "Uploading_Attack"}


def family(label):
    if label == "BenignTraffic":
        return "Benign"
    if label.startswith("DDoS"):
        return "DDoS"
    if label.startswith("DoS"):
        return "DoS"
    if label.startswith("Mirai"):
        return "Mirai"
    if label.startswith("Recon") or label == "VulnerabilityScan":
        return "Recon"
    if label in ("MITM-ArpSpoofing", "DNS_Spoofing"):
        return "Spoofing"
    if label in WEB:
        return "Web"
    if label == "DictionaryBruteForce":
        return "BruteForce"
    return "Other"


def task_labels(labels, task):
    if task == "34class":
        return labels.to_numpy()
    if task == "8class":
        return labels.map(family).to_numpy()
    return np.where(labels == "BenignTraffic", "Benign", "Attack")


print(pd.Series(task_labels(test_df["label"], "8class")).value_counts().to_string())

# %% [markdown]
# ## 4. Class imbalance
#
# DDoS rows outnumber BruteForce rows about 2,700 to 1. A model trained naively learns "always say DDoS" and still gets 73 %
# accuracy. Two common fixes:
#
# * **Undersampling**: throw away most DDoS rows. Simple, but wastes data (and you asked to use the full dataset).
# * **Class weights**: keep every row, but make mistakes on rare classes cost more during training. **We use this.**
#
# The fully "balanced" weight would be `N / (K * n_class)`, which gives the rarest classes a weight of ~1,000 and makes training
# unstable. We use its **square root**: rare classes still count roughly 30x more than DDoS, without wild swings.
# This is called *square-root (or tempered) class weighting*.
#
# We also report **macro-F1** (every class counts equally), not just accuracy.

# %%
def class_weights(y, n_classes):
    counts = np.bincount(y, minlength=n_classes).astype(np.float64)
    w = (len(y) / (n_classes * np.maximum(counts, 1))) ** 0.5
    return w / w[y].mean()          # normalise: average sample weight = 1

# %% [markdown]
# ## 5. The four models
#
# * **Random Forest**: 100 decision trees that vote. Each tree is trained on 500,000 rows drawn from the full training set
#   (`max_samples`), which keeps training time and model size reasonable while every row can still be used.
# * **LightGBM**: boosted trees built one after another, each fixing the previous ones' mistakes. Stops early when the
#   validation score stops improving.
# * **MLP**: 3 layers (46 -> 128 -> 64 -> classes).
# * **1D-CNN**: two small convolution layers slide along the row of features, then a small dense layer.
#
# Neural networks need inputs on similar scales. Features like `Rate` reach millions while flags are 0..1, so for the MLP and
# CNN we apply `sign(x) * log(1 + |x|)` and then standardise with the mean / standard deviation of the **training set only**
# (as the proposal requires: "scaler fitted on training data only").

# %%
import lightgbm as lgb
import torch
import torch.nn as nn

torch.set_num_threads(N_CPU)
torch.manual_seed(0)


def make_rf(weights):
    n = len(Xtr)
    return RandomForestClassifier(
        n_estimators=100, max_depth=20, min_samples_leaf=2,
        max_samples=min(500_000, n) if n > 500_000 else None,
        class_weight={i: float(w) for i, w in enumerate(weights)},
        n_jobs=-1, random_state=0)


def make_lgbm(n_classes):
    return lgb.LGBMClassifier(
        objective="binary" if n_classes == 2 else "multiclass",
        n_estimators=1000, learning_rate=CFG.lgbm_lr, num_leaves=63,
        subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
        n_jobs=-1, random_state=0, verbose=-1)


class MLP(nn.Module):
    def __init__(self, n_in, n_out):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(n_in, 128), nn.ReLU(), nn.Dropout(0.1),
                                 nn.Linear(128, 64), nn.ReLU(),
                                 nn.Linear(64, n_out))

    def forward(self, x):
        return self.net(x)


class CNN1D(nn.Module):
    def __init__(self, n_in, n_out):
        super().__init__()
        self.conv = nn.Sequential(nn.Conv1d(1, 32, 3, padding=1), nn.ReLU(),
                                  nn.Conv1d(32, 32, 3, padding=1), nn.ReLU(),
                                  nn.AdaptiveAvgPool1d(8))
        self.head = nn.Sequential(nn.Flatten(), nn.Linear(32 * 8, 64), nn.ReLU(), nn.Linear(64, n_out))

    def forward(self, x):
        return self.head(self.conv(x.unsqueeze(1)))


def nn_prepare(X, mu=None, sd=None, chunk=500_000):
    """sign(x)*log(1+|x|), then standardise. Done in chunks to keep memory low."""
    Z = np.empty_like(X, dtype=np.float32)
    for i in range(0, len(X), chunk):
        x = X[i:i + chunk]
        Z[i:i + chunk] = np.sign(x) * np.log1p(np.abs(x))
    if mu is None:
        mu = Z.mean(axis=0, dtype=np.float64).astype(np.float32)
        sd = (Z.std(axis=0, dtype=np.float64) + 1e-6).astype(np.float32)
    for i in range(0, len(Z), chunk):
        Z[i:i + chunk] -= mu
        Z[i:i + chunk] /= sd
    return Z, mu, sd


def nn_predict(net, Z, batch=65536):
    net.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(Z), batch):
            out.append(net(torch.from_numpy(Z[i:i + batch])).argmax(1).numpy())
    return np.concatenate(out)


def train_nn(kind, Ztr, ytr, Zva, yva, n_classes, weights):
    net = MLP(Ztr.shape[1], n_classes) if kind == "mlp" else CNN1D(Ztr.shape[1], n_classes)
    opt = torch.optim.Adam(net.parameters(), lr=1e-3)
    loss_fn = nn.CrossEntropyLoss(weight=torch.tensor(weights, dtype=torch.float32))
    Xt, yt = torch.from_numpy(Ztr), torch.from_numpy(ytr.astype(np.int64))
    best_f1, best_state, bs = -1.0, None, 4096
    for ep in range(CFG.epochs):
        net.train()
        perm = torch.randperm(len(Xt))
        for step, i in enumerate(range(0, len(Xt), bs)):
            idx = perm[i:i + bs]
            opt.zero_grad()
            loss = loss_fn(net(Xt[idx]), yt[idx])
            loss.backward()
            opt.step()
            if step % 300 == 0:
                log(f"    {kind} epoch {ep + 1}/{CFG.epochs}  step {step}/{len(Xt) // bs}  loss {loss.item():.4f}")
        f1 = f1_score(yva, nn_predict(net, Zva), average="macro")
        log(f"    {kind} epoch {ep + 1}: validation macro-F1 = {f1:.4f}")
        if f1 > best_f1:
            best_f1, best_state = f1, {k: v.clone() for k, v in net.state_dict().items()}
    net.load_state_dict(best_state)
    return net

# %% [markdown]
# ## 6. Scoring
#
# For every model on `test.csv`:
#
# * **accuracy**, **macro-F1** (main metric), per-class **recall** (saved as CSV)
# * **benign false-alarm rate** (FPR, False Positive Rate): share of normal rows wrongly flagged as an attack
# * **confusion matrix** image (rows = true class, columns = predicted class, each row sums to 1)
# * **model size** (KB, kilobytes) of the saved file, **latency** (ms per single row) and **throughput** (rows per second)
#   on this laptop. The Pi numbers come later.

# %%
SUMMARY_CSV = OUT / "results_summary.csv"


def timing(predict_one, predict_batch, X):
    rows = X[:300]
    predict_one(rows[:1])                                   # warm-up
    t0 = time.perf_counter()
    for i in range(len(rows)):
        predict_one(rows[i:i + 1])
    latency_ms = (time.perf_counter() - t0) / len(rows) * 1000
    big = X[:100_000]
    t0 = time.perf_counter()
    predict_batch(big)
    throughput = len(big) / (time.perf_counter() - t0)
    return latency_ms, throughput


def evaluate(task, model_name, classes, y_true, y_pred, extra):
    acc = accuracy_score(y_true, y_pred)
    mf1 = f1_score(y_true, y_pred, average="macro")
    benign = classes.index("Benign") if "Benign" in classes else classes.index("BenignTraffic")
    is_b = y_true == benign
    fpr = float((y_pred[is_b] != benign).mean()) if is_b.any() else float("nan")

    rep = classification_report(y_true, y_pred, labels=range(len(classes)), target_names=classes,
                                output_dict=True, zero_division=0)
    pd.DataFrame(rep).T.to_csv(OUT / f"report_{task}_{model_name}.csv")

    cm = confusion_matrix(y_true, y_pred, labels=range(len(classes)), normalize="true")
    size = max(6, len(classes) * 0.45)
    fig, ax = plt.subplots(figsize=(size + 2, size))
    ConfusionMatrixDisplay(cm, display_labels=classes).plot(
        ax=ax, cmap="Blues", colorbar=False, xticks_rotation=90,
        include_values=len(classes) <= 10, values_format=".2f")
    ax.set_title(f"{task} - {model_name}  (macro-F1 {mf1:.3f})")
    fig.tight_layout()
    fig.savefig(OUT / f"cm_{task}_{model_name}.png", dpi=110)
    plt.show() if IN_NOTEBOOK else plt.close(fig)

    row = {"task": task, "model": model_name, "n_features": extra.pop("n_features"),
           "accuracy": round(acc, 4), "macro_f1": round(mf1, 4), "benign_fpr": round(fpr, 4), **extra}
    pd.DataFrame([row]).to_csv(SUMMARY_CSV, mode="a", header=not SUMMARY_CSV.exists(), index=False)
    log(f"  RESULT {task:7s} {model_name:5s}  acc {acc:.4f}  macro-F1 {mf1:.4f}  benign-FPR {fpr:.4f}  {extra}")
    return row

# %% [markdown]
# ## 7. Train and score everything
#
# Loop over the tasks (binary, 8-class, 34-class) and models (RF, LightGBM, MLP, 1D-CNN).
# Each finished model is written to `results/results_summary.csv` immediately, so a long run that is stopped half-way
# still keeps its results.

# %%
if SUMMARY_CSV.exists():
    SUMMARY_CSV.unlink()                       # start a fresh summary for this run

Xtr = train_df[FEATURES].to_numpy(np.float32)
Xva = val_df[FEATURES].to_numpy(np.float32)
Xte = test_df[FEATURES].to_numpy(np.float32)
# keep only the labels, free the big tables (saves several GB of RAM)
LAB_TR, LAB_VA, LAB_TE = train_df["label"].copy(), val_df["label"].copy(), test_df["label"].copy()
del train_df, val_df, test_df
import gc
gc.collect()
need_nn = any(m in MODELS for m in ("mlp", "cnn"))
if need_nn:
    Ztr, MU, SD = nn_prepare(Xtr)
    Zva, _, _ = nn_prepare(Xva, MU, SD)
    Zte, _, _ = nn_prepare(Xte, MU, SD)

TRAINED = {}
for task in TASKS:
    lab_tr = task_labels(LAB_TR, task)
    classes = sorted(set(lab_tr))
    cidx = {c: i for i, c in enumerate(classes)}
    ytr = np.array([cidx[c] for c in lab_tr])
    yva = np.array([cidx.get(c, -1) for c in task_labels(LAB_VA, task)])
    yte = np.array([cidx.get(c, -1) for c in task_labels(LAB_TE, task)])
    va_ok, te_ok = yva >= 0, yte >= 0
    K = len(classes)
    w = class_weights(ytr, K)
    log(f"=== TASK {task}: {K} classes, {len(ytr):,} training rows ===")

    for m in MODELS:
        log(f"  training {m} ...")
        t0 = time.time()
        if m == "rf":
            model = make_rf(w).fit(Xtr, ytr)
            train_s = time.time() - t0
            path = MODELS_DIR / f"{task}_rf.joblib"
            joblib.dump(model, path, compress=3)
            pred = model.predict(Xte[te_ok])
            model.set_params(n_jobs=1)
            lat, thr = timing(model.predict, model.predict, Xte)
            model.set_params(n_jobs=-1)
        elif m == "lgbm":
            model = make_lgbm(K)
            model.fit(Xtr, ytr, sample_weight=w[ytr],
                      eval_set=[(Xva[va_ok], yva[va_ok])],
                      callbacks=[lgb.early_stopping(30, verbose=False), lgb.log_evaluation(50)])
            train_s = time.time() - t0
            path = MODELS_DIR / f"{task}_lgbm.txt"
            model.booster_.save_model(str(path), num_iteration=model.best_iteration_)
            joblib.dump(model, MODELS_DIR / f"{task}_lgbm.joblib")
            pred = model.predict(Xte[te_ok])
            lat, thr = timing(model.predict, model.predict, Xte)
        else:
            model = train_nn(m, Ztr, ytr, Zva[va_ok], yva[va_ok], K, w)
            train_s = time.time() - t0
            path = MODELS_DIR / f"{task}_{m}.pt"
            torch.save({"state_dict": model.state_dict(), "kind": m, "classes": classes,
                        "features": FEATURES, "mu": MU, "sd": SD}, path)
            pred = nn_predict(model, Zte[te_ok])
            lat, thr = timing(lambda r: nn_predict(model, r), lambda r: nn_predict(model, r), Zte)

        TRAINED[(task, m)] = model
        evaluate(task, m, classes, yte[te_ok], pred,
                 {"n_features": len(FEATURES), "train_time_s": round(train_s, 1),
                  "model_size_kb": round(path.stat().st_size / 1024, 1),
                  "latency_ms_per_row": round(lat, 3), "throughput_rows_s": int(thr)})

json.dump({"features": FEATURES, "families": {c: family(c) for c in sorted(LAB_TR.unique())}},
          open(MODELS_DIR / "meta.json", "w"), indent=2)

# %% [markdown]
# ## 8. RQ1: how few features are enough? (SHAP feature ranking)
#
# 1. Take the 8-class LightGBM model trained on all 46 features.
# 2. Compute **TreeSHAP** values for 3,000 validation rows: for each row and each feature, how much that feature pushed
#    the prediction. Average the absolute values -> one importance score per feature.
# 3. Retrain LightGBM and Random Forest (8-class) using only the top 5, 10, 15, 20, 25, 30 features; score each on `test.csv`.
# 4. Plot macro-F1 against the number of features. The proposal's question: what is the **smallest** number of features
#    whose macro-F1 is within 0.02 of the all-46 model?

# %%
if not CFG.skip_rq1 and ("8class", "lgbm") in TRAINED:
    import shap

    base = TRAINED[("8class", "lgbm")]
    lab8 = task_labels(LAB_TR, "8class")
    classes8 = sorted(set(lab8))
    c8 = {c: i for i, c in enumerate(classes8)}
    ytr8 = np.array([c8[c] for c in lab8])
    yva8 = np.array([c8.get(c, -1) for c in task_labels(LAB_VA, "8class")])
    yte8 = np.array([c8.get(c, -1) for c in task_labels(LAB_TE, "8class")])
    w8 = class_weights(ytr8, len(classes8))

    log("RQ1: computing SHAP values ...")
    rng = np.random.default_rng(3)
    sample_rows = Xva[rng.choice(len(Xva), min(3000, len(Xva)), replace=False)]
    sv = shap.TreeExplainer(base).shap_values(sample_rows)
    sv = np.abs(np.array(sv))
    feat_axis = [i for i, n in enumerate(sv.shape) if n == len(FEATURES)][-1]
    importance = sv.mean(axis=tuple(i for i in range(sv.ndim) if i != feat_axis))
    ranking = pd.DataFrame({"feature": FEATURES, "mean_abs_shap": importance}) \
        .sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)
    ranking.index += 1
    ranking.to_csv(OUT / "rq1_shap_ranking.csv", index_label="rank")
    print(ranking.head(20).to_string())

    fig, ax = plt.subplots(figsize=(8, 7))
    top = ranking.head(20).iloc[::-1]
    ax.barh(top["feature"], top["mean_abs_shap"], color="#4C72B0")
    ax.set_xlabel("mean |SHAP value|  (average impact on the prediction)")
    ax.set_title("Top 20 features, 8-class LightGBM")
    fig.tight_layout()
    fig.savefig(OUT / "rq1_shap_top20.png", dpi=110)
    plt.show() if IN_NOTEBOOK else plt.close(fig)

    te_ok8, va_ok8 = yte8 >= 0, yva8 >= 0
    rq1_models = [m for m in ("lgbm", "rf") if ("8class", m) in TRAINED]
    full = {m: f1_score(yte8[te_ok8], TRAINED[("8class", m)].predict(Xte[te_ok8]), average="macro")
            for m in rq1_models}
    rq1 = [{"model": m, "k": len(FEATURES), "macro_f1": round(full[m], 4), "features": "all"} for m in rq1_models]
    for k in [k for k in TOPK if k < len(FEATURES)]:
        top_feats = list(ranking["feature"].head(k))
        cols = [FEATURES.index(f) for f in top_feats]
        for m in rq1_models:
            log(f"RQ1: retraining {m} 8-class with top {k} features ...")
            if m == "lgbm":
                mk = make_lgbm(len(classes8))
                mk.fit(Xtr[:, cols], ytr8, sample_weight=w8[ytr8],
                       eval_set=[(Xva[va_ok8][:, cols], yva8[va_ok8])],
                       callbacks=[lgb.early_stopping(30, verbose=False)])
                mk.booster_.save_model(str(MODELS_DIR / f"8class_lgbm_top{k}.txt"), num_iteration=mk.best_iteration_)
            else:
                mk = make_rf(w8).fit(Xtr[:, cols], ytr8)
                joblib.dump(mk, MODELS_DIR / f"8class_rf_top{k}.joblib", compress=3)
            f1k = f1_score(yte8[te_ok8], mk.predict(Xte[te_ok8][:, cols]), average="macro")
            rq1.append({"model": m, "k": k, "macro_f1": round(f1k, 4), "features": ", ".join(top_feats)})
            log(f"RQ1: {m:4s} top {k:2d} features -> macro-F1 {f1k:.4f}  (all {len(FEATURES)}: {full[m]:.4f})")
            del mk
            gc.collect()

    rq1_df = pd.DataFrame(rq1).sort_values(["model", "k"])
    rq1_df["within_2pct"] = rq1_df.apply(lambda r: r["macro_f1"] >= full[r["model"]] - 0.02, axis=1)
    rq1_df.to_csv(OUT / "rq1_f1_vs_features.csv", index=False)

    fig, ax = plt.subplots(figsize=(7.5, 4.8))
    colors = {"lgbm": "#4C72B0", "rf": "#DD8452"}
    names = {"lgbm": "LightGBM", "rf": "Random Forest"}
    for m in rq1_models:
        d = rq1_df[rq1_df["model"] == m]
        answer = int(d[d["within_2pct"]]["k"].min())
        log(f"RQ1 ANSWER ({names[m]}): {answer} features keep macro-F1 within 0.02 of all {len(FEATURES)} ({full[m]:.4f})")
        ax.plot(d["k"], d["macro_f1"], "o-", color=colors[m], label=f"{names[m]} (enough: {answer})")
        ax.axhline(full[m] - 0.02, ls="--", color=colors[m], alpha=0.5)
    ax.set_xlabel("number of features (top-k by SHAP)")
    ax.set_ylabel("macro-F1 on test (8-class)")
    ax.set_title("RQ1: macro-F1 vs number of features (dashed = all features - 0.02)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(OUT / "rq1_f1_vs_features.png", dpi=110)
    plt.show() if IN_NOTEBOOK else plt.close(fig)

# %% [markdown]
# ## 9. Summary
#
# The table below is also in `results/results_summary.csv`. Confusion matrices: `results/cm_<task>_<model>.png`.
# Per-class precision / recall / F1: `results/report_<task>_<model>.csv`.

# %%
summary = pd.read_csv(SUMMARY_CSV)
print(summary.to_string(index=False))
log(f"Done. Results in {OUT}, models in {MODELS_DIR}")
