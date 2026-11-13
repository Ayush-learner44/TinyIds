"""Fresh training run (13 Nov 2026): 4 models x 3 tasks on CICIoT2023, one clean results table.

Separate from everything else: reads only model/cache/*.parquet, writes only model/fresh/results/ and model/fresh/models/.
(pi/, laptop/ and the other model/ scripts are not touched.)

  tasks   : binary (Benign / Attack), 8class (families, DDoS and DoS separate), 34class (exact attack)
  models  : Random Forest, LightGBM (CPU)   |   MLP, 1D-CNN (PyTorch on the GPU if available)
  data    : 20 % stratified sample of train.csv, 20 % of validation.csv (early stopping), FULL test.csv for scoring
  features: the 45 dataset features without IAT (IAT is a capture-timing shortcut, see START.md)

For every model it also makes an EDGE version (what fits a Raspberry Pi):
  RF -> 30 trees, depth 12 | LightGBM -> as many rounds as fit in < 1 MB | MLP / CNN -> INT8 (dynamic quantization)

What is new compared with the old run2 (3 epochs on CPU):
  * neural nets train up to 40 epochs on the GPU, learning rate drops when validation stops improving,
    the best epoch (validation macro-F1) is kept; BatchNorm layers for stable training
  * LightGBM and RF use the same square-root class weights as the nets
  * every number in the table is measured in this run (sizes in bytes on disk, latency = one row at a time on the laptop CPU)

Run:  model\\fresh\\.venv\\Scripts\\python model\\fresh\\train_fresh.py            (all, ~30-60 min)
      ... --tasks binary --models lgbm --sample 0.02                                     (quick test)
"""
import argparse
import io
import json
import time
import warnings
from pathlib import Path

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score

HERE = Path(__file__).resolve().parent
CACHE = HERE.parent / "cache"
RESULTS = HERE / "results"
MODELS = HERE / "models"
RESULTS.mkdir(exist_ok=True)
MODELS.mkdir(exist_ok=True)

p = argparse.ArgumentParser()
p.add_argument("--tasks", default="binary,8class,34class")
p.add_argument("--models", default="rf,lgbm,mlp,cnn")
p.add_argument("--sample", type=float, default=0.2)
p.add_argument("--epochs", type=int, default=40)
p.add_argument("--out", default="fresh_results", help="name of the results CSV (lets trees and nets run separately)")
CFG = p.parse_args()

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
torch.manual_seed(0)
np.random.seed(0)
T0 = time.time()


def log(msg):
    print(f"[{time.time() - T0:7.0f} s] {msg}", flush=True)


# ------------------------------------------------------------------ data
def sample(df, frac, seed):
    """The same fraction of EVERY label, so rare attacks keep their rows."""
    if frac >= 1:
        return df
    rng = np.random.default_rng(seed)
    keep = [rng.choice(i, max(1, int(round(len(i) * frac))), replace=False)
            for i in df.groupby("label", observed=True).indices.values()]
    return df.iloc[np.sort(np.concatenate(keep))].reset_index(drop=True)


WEB = {"SqlInjection", "CommandInjection", "XSS", "BrowserHijacking", "Backdoor_Malware", "Uploading_Attack"}


def family(label):
    if label == "BenignTraffic": return "Benign"
    if label.startswith("DDoS"): return "DDoS"
    if label.startswith("DoS"): return "DoS"
    if label.startswith("Mirai"): return "Mirai"
    if label.startswith("Recon") or label == "VulnerabilityScan": return "Recon"
    if label in ("MITM-ArpSpoofing", "DNS_Spoofing"): return "Spoofing"
    if label in WEB: return "Web"
    return "BruteForce"


def labels_for(task, raw):
    if task == "34class": return raw.to_numpy()
    if task == "8class": return raw.map(family).to_numpy()
    return np.where(raw == "BenignTraffic", "Benign", "Attack")


tr = sample(pd.read_parquet(CACHE / "train.parquet"), CFG.sample, 0)
va = sample(pd.read_parquet(CACHE / "validation.parquet"), 0.2, 1)
te = pd.read_parquet(CACHE / "test.parquet")
FEATURES = [c for c in tr.columns if c not in ("label", "IAT")]
X = {k: d[FEATURES].to_numpy(np.float32) for k, d in (("tr", tr), ("va", va), ("te", te))}
RAW = {"tr": tr["label"], "va": va["label"], "te": te["label"]}
del tr, va, te
log(f"train {len(X['tr']):,} | val {len(X['va']):,} | test {len(X['te']):,} rows, {len(FEATURES)} features, device {DEVICE}")


def class_weights(y, k):
    w = (len(y) / (k * np.maximum(np.bincount(y, minlength=k), 1))) ** 0.5
    return (w / w[y].mean()).astype(np.float32)


# ------------------------------------------------------------------ neural nets
def nn_scale(Xa, mu=None, sd=None):
    """sign(x) * log(1 + |x|), then standardise with the TRAINING mean / std (features range from 0..1 to millions)."""
    Z = np.sign(Xa) * np.log1p(np.abs(Xa))
    if mu is None:
        mu, sd = Z.mean(0), Z.std(0) + 1e-6
    return ((Z - mu) / sd).astype(np.float32), mu, sd


class MLP(nn.Module):
    def __init__(self, n_in, n_out):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(n_in, 256), nn.BatchNorm1d(256), nn.ReLU(), nn.Dropout(0.1),
                                 nn.Linear(256, 128), nn.BatchNorm1d(128), nn.ReLU(),
                                 nn.Linear(128, n_out))

    def forward(self, x):
        return self.net(x)


class CNN1D(nn.Module):
    """Two small convolutions slide along the row of features, then a dense layer."""

    def __init__(self, n_in, n_out):
        super().__init__()
        self.conv = nn.Sequential(nn.Conv1d(1, 32, 3, padding=1), nn.BatchNorm1d(32), nn.ReLU(),
                                  nn.Conv1d(32, 32, 3, padding=1), nn.BatchNorm1d(32), nn.ReLU(), nn.MaxPool1d(3))
        self.head = nn.Sequential(nn.Flatten(), nn.Linear(32 * (n_in // 3), 128), nn.ReLU(), nn.Linear(128, n_out))

    def forward(self, x):
        return self.head(self.conv(x.unsqueeze(1)))


def nn_predict(net, Z, device, batch=65536):
    net.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(Z), batch):
            out.append(net(torch.from_numpy(Z[i:i + batch]).to(device)).argmax(1).cpu().numpy())
    return np.concatenate(out)


def train_nn(kind, Ztr, ytr, Zva, yva, k, w):
    net = (MLP if kind == "mlp" else CNN1D)(Ztr.shape[1], k).to(DEVICE)
    opt = torch.optim.AdamW(net.parameters(), lr=2e-3, weight_decay=1e-4)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="max", factor=0.5, patience=2)
    loss_fn = nn.CrossEntropyLoss(weight=torch.tensor(w, device=DEVICE))
    Xt, yt = torch.from_numpy(Ztr).to(DEVICE), torch.from_numpy(ytr.astype(np.int64)).to(DEVICE)
    best, best_state, bad, bs = -1, None, 0, 4096
    for ep in range(CFG.epochs):
        net.train()
        perm = torch.randperm(len(Xt), device=DEVICE)
        for i in range(0, len(Xt), bs):
            idx = perm[i:i + bs]
            opt.zero_grad()
            loss_fn(net(Xt[idx]), yt[idx]).backward()
            opt.step()
        f1 = f1_score(yva, nn_predict(net, Zva, DEVICE), average="macro")
        sched.step(f1)
        if f1 > best:
            best, bad = f1, 0
            best_state = {n: t.detach().cpu().clone() for n, t in net.state_dict().items()}
        else:
            bad += 1
        log(f"    {kind} epoch {ep + 1:2d}: val macro-F1 {f1:.4f} (best {best:.4f})")
        if bad >= 6:
            break
    net = net.cpu()
    net.load_state_dict(best_state)
    return net.eval()


def predict_rows(net, Z):
    """One row at a time, exactly like the live IDS (INT8 dynamic picks its scale per call, so big batches distort it)."""
    with torch.no_grad():
        return np.array([int(net(torch.from_numpy(Z[i:i + 1])).argmax(1)) for i in range(len(Z))])


def int8(net):
    """Dynamic INT8 quantization of the Linear layers (weights stored as 8-bit integers)."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return torch.ao.quantization.quantize_dynamic(net, {nn.Linear}, dtype=torch.qint8).eval()


def torch_bytes(net):
    buf = io.BytesIO()
    torch.save(net.state_dict(), buf)
    return buf.tell()


# ------------------------------------------------------------------ LightGBM / RF helpers
def lgbm_train(Xtr, ytr, Xva, yva, k, w):
    params = {"objective": "binary" if k == 2 else "multiclass", "num_class": 1 if k == 2 else k,
              "learning_rate": 0.05 if k > 10 else 0.1, "num_leaves": 63,     # 34 classes: gentler steps
              "metric": "binary_error" if k == 2 else "multi_error",           # stop on mistakes, not on log-loss "max_bin": 63, "bagging_fraction": 0.8, "bagging_freq": 1,
              "feature_fraction": 0.8, "verbose": -1, "seed": 0, "num_threads": 0}
    return lgb.train(params, lgb.Dataset(Xtr, ytr, weight=w[ytr]), num_boost_round=1000,
                     valid_sets=[lgb.Dataset(Xva, yva)], callbacks=[lgb.early_stopping(60, verbose=False)])


def lgbm_predict(b, Xa, rounds=None):
    p_ = b.predict(Xa, num_iteration=rounds)
    return (p_ > 0.5).astype(int) if p_.ndim == 1 else p_.argmax(1)


def lgbm_small(Xtr, ytr, Xva, yva, k, w):
    """Edge version: 15-leaf trees, as many rounds as fit in < 1 MB."""
    params = {"objective": "binary" if k == 2 else "multiclass", "num_class": 1 if k == 2 else k,
              "learning_rate": 0.1 if k > 10 else 0.2, "num_leaves": 15, "max_bin": 63, "bagging_fraction": 0.8, "bagging_freq": 1,
              "feature_fraction": 0.8, "verbose": -1, "seed": 0}
    b = lgb.train(params, lgb.Dataset(Xtr, ytr, weight=w[ytr]), num_boost_round=400,
                  valid_sets=[lgb.Dataset(Xva, yva)], callbacks=[lgb.early_stopping(30, verbose=False)])
    rounds = 1
    for r in range(1, b.current_iteration() + 1):
        if len(b.model_to_string(num_iteration=r).encode()) >= 1_000_000:
            break
        rounds = r
    return b, min(rounds, b.best_iteration or rounds)


def rf_train(Xtr, ytr, w, small=False):
    rf = RandomForestClassifier(n_estimators=30 if small else 100, max_depth=12 if small else 20, min_samples_leaf=2,
                                max_samples=min(500_000, len(Xtr)), class_weight={i: float(v) for i, v in enumerate(w)},
                                n_jobs=-1, random_state=0)
    return rf.fit(Xtr, ytr)


def file_bytes(obj):
    buf = io.BytesIO()
    joblib.dump(obj, buf, compress=3)
    return buf.tell()


def latency_ms(predict_one, Xa, n=300):
    """Average time to classify ONE row (like the live IDS), on the laptop CPU."""
    rows = Xa[:n]
    predict_one(rows[:1])
    t = time.perf_counter()
    for i in range(n):
        predict_one(rows[i:i + 1])
    return (time.perf_counter() - t) * 1000 / n


# ------------------------------------------------------------------ main loop
TABLE = []


def record(task, model, variant, y_true, y_pred, classes, size_bytes, lat, train_s):
    benign = classes.index("Benign") if "Benign" in classes else classes.index("BenignTraffic")
    is_benign = y_true == benign
    row = {"task": task, "model": model, "variant": variant,
           "accuracy": round(accuracy_score(y_true, y_pred), 4),
           "macro_f1": round(f1_score(y_true, y_pred, average="macro"), 4),
           "benign_false_alarm": round(float((y_pred[is_benign] != benign).mean()), 4),
           "size_kb": round(size_bytes / 1024, 1), "latency_ms": round(lat, 3), "train_s": round(train_s, 1)}
    TABLE.append(row)
    pd.DataFrame(TABLE).to_csv(RESULTS / f"{CFG.out}.csv", index=False)
    log(f"  {task:8s} {model:5s} {variant:22s} acc {row['accuracy']:.4f}  macro-F1 {row['macro_f1']:.4f}  "
        f"benign FA {row['benign_false_alarm']:.4f}  {row['size_kb']:9.1f} KB  {row['latency_ms']:.3f} ms")
    if variant == "full":
        rep = classification_report(y_true, y_pred, labels=range(len(classes)), target_names=classes,
                                    output_dict=True, zero_division=0)
        pd.DataFrame(rep).T.to_csv(RESULTS / f"report_{task}_{model}.csv")


for task in CFG.tasks.split(","):
    y_s = {k: labels_for(task, RAW[k]) for k in RAW}
    classes = sorted(set(y_s["tr"]))
    cid = {c: i for i, c in enumerate(classes)}
    y = {k: np.array([cid[c] for c in v]) for k, v in y_s.items()}
    K, w = len(classes), class_weights(y["tr"], len(classes))
    log(f"=== {task}: {K} classes")

    if "rf" in CFG.models:
        for small in (False, True):
            t = time.time()
            rf = rf_train(X["tr"], y["tr"], w, small)
            tt = time.time() - t
            rf.n_jobs = 1                                   # time ONE row on one core (all cores = big start-up cost per call)
            record(task, "rf", "edge: 30 trees d12" if small else "full", y["te"], rf.predict(X["te"]), classes,
                   file_bytes(rf), latency_ms(rf.predict, X["te"], 100), tt)
            if not small:
                joblib.dump(rf, MODELS / f"{task}_rf.joblib", compress=3)
            del rf

    if "lgbm" in CFG.models:
        t = time.time()
        b = lgbm_train(X["tr"], y["tr"], X["va"], y["va"], K, w)
        tt = time.time() - t
        b.save_model(str(MODELS / f"{task}_lgbm.txt"), num_iteration=b.best_iteration)
        record(task, "lgbm", f"full ({b.best_iteration} rds)",
               y["te"], lgbm_predict(b, X["te"], b.best_iteration), classes,
               len(b.model_to_string(num_iteration=b.best_iteration).encode()),
               latency_ms(lambda r: b.predict(r, num_iteration=b.best_iteration), X["te"]), tt)
        t = time.time()
        s, rounds = lgbm_small(X["tr"], y["tr"], X["va"], y["va"], K, w)
        tt = time.time() - t
        s.save_model(str(MODELS / f"{task}_lgbm_edge.txt"), num_iteration=rounds)
        record(task, "lgbm", f"edge: <1MB ({rounds} rds)", y["te"], lgbm_predict(s, X["te"], rounds), classes,
               len(s.model_to_string(num_iteration=rounds).encode()),
               latency_ms(lambda r: s.predict(r, num_iteration=rounds), X["te"]), tt)

    for kind in [m for m in ("mlp", "cnn") if m in CFG.models]:
        Ztr, mu, sd = nn_scale(X["tr"])
        Zva, _, _ = nn_scale(X["va"], mu, sd)
        Zte, _, _ = nn_scale(X["te"], mu, sd)
        t = time.time()
        net = train_nn(kind, Ztr, y["tr"], Zva, y["va"], K, w)
        tt = time.time() - t
        torch.save({"state": net.state_dict(), "mu": mu, "sd": sd, "classes": classes}, MODELS / f"{task}_{kind}.pt")
        torch.set_num_threads(1)
        lat = latency_ms(lambda r: net(torch.from_numpy(r)), Zte)
        torch.set_num_threads(8)
        record(task, kind, "full (fp32)", y["te"], nn_predict(net, Zte, "cpu"), classes, torch_bytes(net), lat, tt)
        q = int8(net)
        torch.set_num_threads(1)
        lat = latency_ms(lambda r: q(torch.from_numpy(r)), Zte)
        torch.set_num_threads(8)
        sub = np.random.default_rng(3).choice(len(Zte), 50_000, replace=False)     # one-row scoring is slow: 50k rows
        record(task, kind, "edge: INT8 (50k rows)", y["te"][sub], predict_rows(q, Zte[sub]), classes, torch_bytes(q), lat, 0)
        record(task, kind, "fp32 on same 50k", y["te"][sub], nn_predict(net, Zte[sub], "cpu"), classes, torch_bytes(net), 0, 0)
        del Ztr, Zva, Zte

json.dump({"features": FEATURES, "sample": CFG.sample, "epochs_max": CFG.epochs, "device": DEVICE,
           "gpu": torch.cuda.get_device_name(0) if DEVICE == "cuda" else None},
          open(RESULTS / f"{CFG.out}_info.json", "w"), indent=2)
log("done -> " + str(RESULTS / f"{CFG.out}.csv"))
