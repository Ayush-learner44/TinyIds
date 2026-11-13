"""RQ2 benchmark on the Raspberry Pi: size, RAM, speed, accuracy (and optionally energy) of every compressed model.

Every model is measured in its own fresh Python process, so the RAM numbers do not mix.

  ./venv/bin/python benchmark/rq2_benchmark.py                      all models -> table + benchmark/results_pi.csv
  ./venv/bin/python benchmark/rq2_benchmark.py --energy mlp_int8    energy test for one model (needs the USB meter)
"""
import argparse
import json
import resource
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import psutil

HERE = Path(__file__).resolve().parent


class TestData:
    def __init__(self):
        d = np.load(HERE / "bench_data.npz")
        self.X, self.y = d["X"], d["y"]
        names = list(d["features45"])
        self.columns = {"all45": list(range(len(names))),
                        "top15": [names.index(f) for f in d["top15"]],
                        "live30": [names.index(f) for f in d["live30"]]}
        self.nn_mean, self.nn_std = d["nn_mean"], d["nn_std"]

    def inputs_for(self, model):
        X = self.X[:, self.columns[model.columns]]
        if model.neural:                                   # same preprocessing as in training
            X = ((np.sign(X) * np.log1p(np.abs(X)) - self.nn_mean) / self.nn_std).astype(np.float32)
        return np.ascontiguousarray(X)


class Model:
    """One model file + how to feed it + how to read its answer (0 = Attack, 1 = Benign)."""

    def __init__(self, name, file, columns, neural=False, one_window_at_a_time=False):
        self.name, self.file, self.columns, self.neural = name, file, columns, neural
        self.one_window_at_a_time = one_window_at_a_time       # INT8 dynamic models must get one window per call

    def load(self):
        path = str(HERE / "models" / self.file)
        if self.file.endswith(".txt"):
            import lightgbm as lgb
            booster = lgb.Booster(model_file=path)
            self.predict = lambda X: (booster.predict(X) > 0.5).astype(int)
            self.explain = lambda X: booster.predict(X, pred_contrib=True)
        else:
            import onnxruntime as ort
            options = ort.SessionOptions()
            options.intra_op_num_threads = 1
            session = ort.InferenceSession(path, options, providers=["CPUExecutionProvider"])
            name = session.get_inputs()[0].name
            run = lambda X: session.run(None, {name: X})[0]
            self.predict = (lambda X: run(X).argmax(1)) if self.neural else (lambda X: np.asarray(run(X)).astype(int))
            self.explain = None

    def predict_all(self, X):
        if self.one_window_at_a_time:
            return np.array([self.predict(X[i:i + 1])[0] for i in range(len(X))])
        return self.predict(X)


MODELS = [
    Model("ids_lightgbm", "ids_lightgbm.txt", "live30"),
    Model("lightgbm_pruned", "lightgbm_pruned.onnx", "top15"),
    Model("randomforest_pruned", "randomforest_pruned.onnx", "top15"),
    Model("mlp_fp32", "mlp_fp32.onnx", "all45", neural=True),
    Model("mlp_int8", "mlp_int8.onnx", "all45", neural=True, one_window_at_a_time=True),
    Model("cnn_fp32", "cnn_fp32.onnx", "all45", neural=True),
    Model("cnn_int8", "cnn_int8.onnx", "all45", neural=True),
]
BY_NAME = {m.name: m for m in MODELS}


def macro_f1(y, p):
    scores = []
    for c in (0, 1):
        tp, fp, fn = np.sum((p == c) & (y == c)), np.sum((p == c) & (y != c)), np.sum((p != c) & (y == c))
        scores.append(2 * tp / (2 * tp + fp + fn) if tp else 0.0)
    return float(np.mean(scores))


def measure_one(name):
    """Runs inside a fresh process. Prints one JSON line."""
    model, data = BY_NAME[name], TestData()
    process = psutil.Process()
    ram_before = process.memory_info().rss / 2**20
    model.load()
    X = data.inputs_for(model)
    model.predict(X[:1])                                       # warm-up
    ram_loaded = process.memory_info().rss / 2**20

    start = time.perf_counter()                                # latency: one window per call
    for i in range(500):
        model.predict(X[i:i + 1])
    latency_ms = (time.perf_counter() - start) / 500 * 1000

    start = time.perf_counter()                                # throughput: all 20,000 windows
    predictions = model.predict_all(X)
    throughput = len(X) / (time.perf_counter() - start)

    shap_ms = None
    if model.explain:
        start = time.perf_counter()
        for i in range(100):
            model.explain(X[i:i + 1])
        shap_ms = (time.perf_counter() - start) / 100 * 1000

    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024     # Linux: KB -> MB
    print(json.dumps({
        "model": name, "size_kb": round((HERE / "models" / model.file).stat().st_size / 1024, 1),
        "features": len(data.columns[model.columns]),
        "accuracy": round(float(np.mean(predictions == data.y)), 4), "macro_f1": round(macro_f1(data.y, predictions), 4),
        "latency_ms": round(latency_ms, 3), "throughput_per_s": int(throughput), "shap_ms": shap_ms and round(shap_ms, 3),
        "ram_model_mb": round(ram_loaded - ram_before, 1), "ram_peak_mb": round(peak_mb, 1)}))


def run_all():
    rows = []
    for m in MODELS:
        print(f"measuring {m.name} ...", flush=True)
        out = subprocess.run([sys.executable, __file__, "--one", m.name], capture_output=True, text=True)
        if out.returncode != 0:
            print(out.stderr[-500:])
            continue
        rows.append(json.loads(out.stdout.strip().splitlines()[-1]))
    keys = list(rows[0])
    print("\n" + "  ".join(f"{k:>16}" for k in keys))
    for r in rows:
        print("  ".join(f"{str(r[k]):>16}" for k in keys))
    with open(HERE / "results_pi.csv", "w") as f:
        f.write(",".join(keys) + "\n")
        f.writelines(",".join(str(r[k]) for k in keys) + "\n" for r in rows)
    print(f"\nsaved {HERE / 'results_pi.csv'}")


def energy_test(name, seconds=30):
    """Read the USB power meter during an idle phase and during a busy phase; energy = extra power x time / windows."""
    model, data = BY_NAME[name], TestData()
    model.load()
    X = data.inputs_for(model)
    print(f"IDLE phase: {seconds} s. Read the meter (watts) now and write it down ...", flush=True)
    time.sleep(seconds)
    print(f"BUSY phase: {seconds} s of {name} classifying one window at a time. Read the meter now ...", flush=True)
    done, end = 0, time.time() + seconds
    while time.time() < end:
        model.predict(X[done % len(X):done % len(X) + 1])
        done += 1
    print(f"{done:,} windows in {seconds} s")
    try:
        idle = float(input("meter reading in the IDLE phase (W): "))
        busy = float(input("meter reading in the BUSY phase (W): "))
        mj = (busy - idle) * seconds / done * 1000
        print(f"energy: {mj:.4f} mJ per window  =  {mj * 1000:.1f} mJ per 1,000 windows")
    except ValueError:
        print("no numbers entered, skipped the calculation")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--one", help=argparse.SUPPRESS)
    parser.add_argument("--energy", choices=list(BY_NAME))
    args = parser.parse_args()
    if args.one:
        measure_one(args.one)
    elif args.energy:
        energy_test(args.energy)
    else:
        run_all()
