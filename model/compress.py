"""TinyIDS step 6: compression and quantization (RQ2).

For every model of run 2 (no IAT) it builds several versions and scores each one on test.csv:

  LightGBM / Random Forest : original  ->  pruned (fewer, smaller trees, top-15 features, LightGBM max_bin 63)
                             ->  pruned exported to ONNX (run with ONNX Runtime)
  MLP / 1D-CNN             : original PyTorch  ->  ONNX float32  ->  ONNX INT8 dynamic  ->  ONNX INT8 static

Measured for each version: file size (KB), accuracy, macro-F1, F1 loss vs the original,
latency for one window (ms) and throughput (windows/s) on this laptop.

Run:        python compress.py                       (binary + 8-class, 20% training sample for the pruned trees)
Quick test: python compress.py --sample 0.02 --test-sample 0.05
"""
import argparse
import json
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

warnings.filterwarnings("ignore")
import logging
logging.getLogger().setLevel(logging.ERROR)   # hide ONNX Runtime "consider pre-processing" notices

HERE = Path(__file__).resolve().parent
p = argparse.ArgumentParser()
p.add_argument("--tasks", default="binary,8class")
p.add_argument("--src", default="run2", help="trained models to start from: models_<src>/, results_<src>/")
p.add_argument("--sample", type=float, default=0.2, help="training fraction for the pruned trees")
p.add_argument("--test-sample", type=float, default=1.0)
p.add_argument("--topk", type=int, default=15, help="features kept by the pruned trees (SHAP ranking)")
p.add_argument("--run-name", default="quant1")
CFG = p.parse_args()

SRC_MODELS = HERE / f"models_{CFG.src}"
SRC_RESULTS = HERE / f"results_{CFG.src}"
OUT = HERE / f"results_{CFG.run_name}"
MOUT = HERE / f"models_{CFG.run_name}"
OUT.mkdir(exist_ok=True)
MOUT.mkdir(exist_ok=True)
T0 = time.time()


def log(m):
    print(f"[{int(time.time() - T0):4d}s] {m}", flush=True)


# ---------------------------------------------------------------- data
WEB = {"SqlInjection", "CommandInjection", "XSS", "BrowserHijacking", "Backdoor_Malware", "Uploading_Attack"}


def family(l):
    if l == "BenignTraffic": return "Benign"
    if l.startswith("DDoS"): return "DDoS"
    if l.startswith("DoS"): return "DoS"
    if l.startswith("Mirai"): return "Mirai"
    if l.startswith("Recon") or l == "VulnerabilityScan": return "Recon"
    if l in ("MITM-ArpSpoofing", "DNS_Spoofing"): return "Spoofing"
    if l in WEB: return "Web"
    return "BruteForce"


def task_labels(lab, task):
    if task == "8class":
        return lab.map(family).to_numpy()
    return np.where(lab == "BenignTraffic", "Benign", "Attack")


def sample(df, frac, seed):
    if frac >= 1:
        return df
    rng = np.random.default_rng(seed)
    keep = [rng.choice(i, max(1, int(round(len(i) * frac))), replace=False)
            for i in df.groupby("label", observed=True).indices.values()]
    return df.iloc[np.sort(np.concatenate(keep))].reset_index(drop=True)


FEATURES = json.load(open(SRC_MODELS / "meta.json"))["features"]          # 45 features, no IAT
RANKING = pd.read_csv(SRC_RESULTS / "rq1_shap_ranking.csv")["feature"].tolist()
TOP = [f for f in RANKING if f in FEATURES][:CFG.topk]
log(f"{len(FEATURES)} features; pruned trees use top {CFG.topk}: {', '.join(TOP)}")

tr = sample(pd.read_parquet(HERE / "cache" / "train.parquet"), CFG.sample, 0)
va = sample(pd.read_parquet(HERE / "cache" / "validation.parquet"), 0.2, 1)
te = sample(pd.read_parquet(HERE / "cache" / "test.parquet"), CFG.test_sample, 2)
Xtr, Xva, Xte = (d[FEATURES].to_numpy(np.float32) for d in (tr, va, te))
TOP_IDX = [FEATURES.index(f) for f in TOP]
LAB = {"tr": tr["label"], "va": va["label"], "te": te["label"]}
del tr, va, te
log(f"train {len(Xtr):,} | val {len(Xva):,} | test {len(Xte):,} rows")

# ---------------------------------------------------------------- measuring
ROWS = []


def kb(path):
    return round(Path(path).stat().st_size / 1024, 1)


def measure(task, model, variant, fmt, path, predict, X, y, n_feat, ref_f1=None):
    pred = predict(X)
    acc, mf1 = accuracy_score(y, pred), f1_score(y, pred, average="macro")
    one = X[:300]
    predict(one[:1])
    t = time.perf_counter()
    for i in range(len(one)):
        predict(one[i:i + 1])
    lat = (time.perf_counter() - t) / len(one) * 1000
    big = X[:100_000]
    t = time.perf_counter()
    predict(big)
    thr = len(big) / (time.perf_counter() - t)
    row = {"task": task, "model": model, "variant": variant, "format": fmt, "n_features": n_feat,
           "size_kb": kb(path), "accuracy": round(acc, 4), "macro_f1": round(mf1, 4),
           "f1_change": None if ref_f1 is None else round(mf1 - ref_f1, 4),
           "latency_ms": round(lat, 3), "throughput_per_s": int(thr)}
    ROWS.append(row)
    pd.DataFrame(ROWS).to_csv(OUT / "quant_results.csv", index=False)
    log(f"  {task:7s} {model:5s} {variant:22s} {row['size_kb']:>9} KB  F1 {mf1:.4f}"
        f"{'' if ref_f1 is None else f' ({mf1 - ref_f1:+.4f})'}  {lat:.3f} ms/window  {int(thr):,}/s")
    return mf1


def failed(task, model, variant, err):
    ROWS.append({"task": task, "model": model, "variant": variant, "format": f"FAILED: {str(err)[:120]}"})
    pd.DataFrame(ROWS).to_csv(OUT / "quant_results.csv", index=False)
    log(f"  {task:7s} {model:5s} {variant:22s} FAILED: {str(err)[:200]}")


# ---------------------------------------------------------------- tools
import lightgbm as lgb
import onnxruntime as ort
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType as SkFloat
from sklearn.ensemble import RandomForestClassifier
from onnxruntime.quantization import (quantize_dynamic, quantize_static, QuantType, QuantFormat,
                                      CalibrationDataReader)
import torch
import torch.nn as nn


def onnx_predictor(path):
    so = ort.SessionOptions()
    so.log_severity_level = 3
    s = ort.InferenceSession(str(path), so, providers=["CPUExecutionProvider"])
    name = s.get_inputs()[0].name
    return lambda X: s.run(None, {name: np.ascontiguousarray(X, dtype=np.float32)})[0]


def onnx_argmax(path, one_by_one=False):
    """one_by_one=True: classify each window separately, as the live IDS does.
    Needed for INT8 *dynamic* models: they pick their 8-bit scale from the whole input batch, so a few extreme rows
    in a big batch would squash all other rows into a couple of values."""
    run = onnx_predictor(path)
    if not one_by_one:
        return lambda X: run(X).argmax(1)
    return lambda X: np.array([run(X[i:i + 1]).argmax(1)[0] for i in range(len(X))])


def class_weights(y, k):
    c = np.bincount(y, minlength=k).astype(float)
    w = (len(y) / (k * np.maximum(c, 1))) ** 0.5
    return w / w[y].mean()


class MLP(nn.Module):
    def __init__(self, n_in, n_out):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(n_in, 128), nn.ReLU(), nn.Dropout(0.1),
                                 nn.Linear(128, 64), nn.ReLU(), nn.Linear(64, n_out))

    def forward(self, x):
        return self.net(x)


class CNN1D(nn.Module):
    def __init__(self, n_in, n_out):
        super().__init__()
        self.conv = nn.Sequential(nn.Conv1d(1, 32, 3, padding=1), nn.ReLU(),
                                  nn.Conv1d(32, 32, 3, padding=1), nn.ReLU(), nn.AdaptiveAvgPool1d(8))
        self.head = nn.Sequential(nn.Flatten(), nn.Linear(32 * 8, 64), nn.ReLU(), nn.Linear(64, n_out))

    def forward(self, x):
        return self.head(self.conv(x.unsqueeze(1)))


class MatPool(nn.Module):
    """Exact replacement for AdaptiveAvgPool1d(out) on a fixed input length, as a matrix multiplication.
    ONNX cannot export adaptive pooling when the length (45) is not a multiple of the output (8)."""
    def __init__(self, length, out):
        super().__init__()
        P = np.zeros((length, out), dtype=np.float32)
        for j in range(out):
            a, b = (j * length) // out, -((-(j + 1) * length) // out)
            P[a:b, j] = 1.0 / (b - a)
        self.register_buffer("P", torch.from_numpy(P))

    def forward(self, x):
        return x @ self.P


def nn_prepare(X, mu, sd):
    Z = np.sign(X) * np.log1p(np.abs(X))
    return ((Z - mu) / sd).astype(np.float32)


class Calib(CalibrationDataReader):
    def __init__(self, Z, name):
        self.it = iter([{name: Z[i:i + 1]} for i in range(len(Z))])

    def get_next(self):
        return next(self.it, None)


def export_onnx(net, n_in, path):
    dummy = torch.zeros(1, n_in)
    try:
        torch.onnx.export(net, dummy, str(path), input_names=["input"], output_names=["logits"],
                          dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
                          opset_version=17, dynamo=False)
    except TypeError:
        torch.onnx.export(net, dummy, str(path), input_names=["input"], output_names=["logits"],
                          dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}}, opset_version=17)


# ---------------------------------------------------------------- main loop
for task in [t.strip() for t in CFG.tasks.split(",")]:
    ytr_s, yva_s, yte_s = (task_labels(LAB[k], task) for k in ("tr", "va", "te"))
    classes = sorted(set(ytr_s))
    cid = {c: i for i, c in enumerate(classes)}
    ytr, yva, yte = (np.array([cid[c] for c in s]) for s in (ytr_s, yva_s, yte_s))
    K = len(classes)
    w = class_weights(ytr, K)
    log(f"=== {task}: {K} classes ===")

    # ---------- LightGBM
    ref = measure(task, "lgbm", "original", "LightGBM .txt", SRC_MODELS / f"{task}_lgbm.txt",
                  joblib.load(SRC_MODELS / f"{task}_lgbm.joblib").predict, Xte, yte, len(FEATURES))
    m = lgb.LGBMClassifier(objective="binary" if K == 2 else "multiclass", n_estimators=150, learning_rate=0.1,
                           num_leaves=15, max_bin=63, subsample=0.8, subsample_freq=1, colsample_bytree=0.8,
                           n_jobs=-1, verbose=-1, random_state=0)
    m.fit(Xtr[:, TOP_IDX], ytr, sample_weight=w[ytr], eval_set=[(Xva[:, TOP_IDX], yva)],
          callbacks=[lgb.early_stopping(20, verbose=False)])
    txt = MOUT / f"{task}_lgbm_pruned.txt"
    m.booster_.save_model(str(txt), num_iteration=m.best_iteration_)
    measure(task, "lgbm", f"pruned ({m.best_iteration_} rounds)", "LightGBM .txt", txt,
            lambda X: m.predict(X[:, TOP_IDX]), Xte, yte, len(TOP), ref)
    try:
        onx = convert_lightgbm(m.booster_, initial_types=[("input", FloatTensorType([None, len(TOP)]))],
                               zipmap=False, target_opset=15)
        path = MOUT / f"{task}_lgbm_pruned.onnx"
        path.write_bytes(onx.SerializeToString())
        run = onnx_predictor(path)
        measure(task, "lgbm", "pruned -> ONNX", "ONNX", path,
                lambda X: np.asarray(run(X[:, TOP_IDX])).astype(int), Xte, yte, len(TOP), ref)
    except Exception as e:
        failed(task, "lgbm", "pruned -> ONNX", e)

    # ---------- Random Forest
    rf = joblib.load(SRC_MODELS / f"{task}_rf.joblib")
    rf.set_params(n_jobs=1)          # 1 core: per-window latency like on the Pi
    ref = measure(task, "rf", "original", "joblib", SRC_MODELS / f"{task}_rf.joblib",
                  rf.predict, Xte, yte, len(FEATURES))
    del rf
    rfp = RandomForestClassifier(n_estimators=30, max_depth=12, min_samples_leaf=5,
                                 max_samples=min(200_000, len(Xtr)),
                                 class_weight={i: float(v) for i, v in enumerate(w)}, n_jobs=-1, random_state=0)
    rfp.fit(Xtr[:, TOP_IDX], ytr)
    rfp.set_params(n_jobs=1)
    path = MOUT / f"{task}_rf_pruned.joblib"
    joblib.dump(rfp, path, compress=3)
    measure(task, "rf", "pruned (30 trees, depth 12)", "joblib", path,
            lambda X: rfp.predict(X[:, TOP_IDX]), Xte, yte, len(TOP), ref)
    try:
        onx = convert_sklearn(rfp, initial_types=[("input", SkFloat([None, len(TOP)]))],
                              options={id(rfp): {"zipmap": False}}, target_opset=17)
        path = MOUT / f"{task}_rf_pruned.onnx"
        path.write_bytes(onx.SerializeToString())
        run = onnx_predictor(path)
        measure(task, "rf", "pruned -> ONNX", "ONNX", path,
                lambda X: np.asarray(run(X[:, TOP_IDX])).astype(int), Xte, yte, len(TOP), ref)
    except Exception as e:
        failed(task, "rf", "pruned -> ONNX", e)

    # ---------- MLP and 1D-CNN
    for kind in ("mlp", "cnn"):
        ck = torch.load(SRC_MODELS / f"{task}_{kind}.pt", weights_only=False)
        net = (MLP if kind == "mlp" else CNN1D)(len(ck["features"]), len(ck["classes"]))
        net.load_state_dict(ck["state_dict"])
        net.eval()
        Zte = nn_prepare(Xte, ck["mu"], ck["sd"])
        if kind == "cnn":                                   # swap the pooling layer for its exact matrix version
            probe = torch.from_numpy(Zte[:2000])
            with torch.no_grad():
                before = net(probe)
                net.conv[4] = MatPool(len(ck["features"]), 8)
                after = net(probe)
            assert torch.allclose(before, after, atol=1e-5), "MatPool is not equivalent"
            log("  cnn: AdaptiveAvgPool1d replaced by an equivalent matrix (outputs identical)")

        def torch_pred(Z, net=net):
            with torch.no_grad():
                return np.concatenate([net(torch.from_numpy(Z[i:i + 65536])).argmax(1).numpy()
                                       for i in range(0, len(Z), 65536)])

        ref = measure(task, kind, "original (PyTorch fp32)", "PyTorch .pt", SRC_MODELS / f"{task}_{kind}.pt",
                      torch_pred, Zte, yte, len(FEATURES))
        fp32 = MOUT / f"{task}_{kind}_fp32.onnx"
        try:
            export_onnx(net, len(ck["features"]), fp32)
            measure(task, kind, "ONNX fp32", "ONNX", fp32, onnx_argmax(fp32), Zte, yte, len(FEATURES), ref)
        except Exception as e:
            failed(task, kind, "ONNX fp32", e)
            continue
        dyn = MOUT / f"{task}_{kind}_int8_dynamic.onnx"
        try:
            quantize_dynamic(str(fp32), str(dyn), weight_type=QuantType.QInt8)
            measure(task, kind, "ONNX INT8 dynamic", "ONNX INT8", dyn, onnx_argmax(dyn, one_by_one=True), Zte, yte, len(FEATURES), ref)
        except Exception as e:
            failed(task, kind, "ONNX INT8 dynamic", e)
        sta = MOUT / f"{task}_{kind}_int8_static.onnx"
        try:
            rng = np.random.default_rng(5)
            calib = nn_prepare(Xtr[rng.choice(len(Xtr), 1000, replace=False)], ck["mu"], ck["sd"])
            quantize_static(str(fp32), str(sta), Calib(calib, "input"), quant_format=QuantFormat.QDQ,
                            activation_type=QuantType.QUInt8, weight_type=QuantType.QInt8)
            measure(task, kind, "ONNX INT8 static", "ONNX INT8", sta, onnx_argmax(sta), Zte, yte, len(FEATURES), ref)
        except Exception as e:
            failed(task, kind, "ONNX INT8 static", e)

log("done")
print(pd.DataFrame(ROWS).to_string(index=False))
