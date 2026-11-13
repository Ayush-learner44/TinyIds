"""Compare the old 7 MB models (models_big/) with the small live ones (models/, < 1 MB) ON THE PI.

No network traffic: uses 2,000 test windows from bench_data.npz (CICIoT2023 test set).
For each model folder: file sizes, model time per window, SHAP time per alert, and how often the
small family model gives the same answer as the big one.

Run on the Pi:  cd ~/tinyids && ./venv/bin/python benchmark/compare_models.py
"""
import json
import time
from pathlib import Path

import lightgbm as lgb
import numpy as np

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
data = np.load(HERE / "bench_data.npz")
all_features = list(data["features45"])


def load(folder):
    meta = json.load(open(ROOT / folder / "meta.json"))
    columns = [all_features.index(f) for f in meta["features"]]
    X = data["X"][:2000][:, columns].astype(np.float32)
    binary = lgb.Booster(model_file=str(ROOT / folder / "binary.txt"))
    family = lgb.Booster(model_file=str(ROOT / folder / "family.txt"))
    return X, binary, family


def ms_per_call(function, rows, repeat):
    times = []
    for i in range(repeat):
        row = rows[i % len(rows): i % len(rows) + 1]          # ONE window at a time, like the live IDS
        start = time.perf_counter()
        function(row)
        times.append((time.perf_counter() - start) * 1000)
    return np.mean(times), np.percentile(times, 95)


answers = {}
for folder in ("models_big", "models"):
    X, binary, family = load(folder)
    size_kb = [(ROOT / folder / f).stat().st_size / 1024 for f in ("binary.txt", "family.txt")]
    model_mean, model_p95 = ms_per_call(lambda r: (binary.predict(r), family.predict(r)), X, 300)
    shap_mean, shap_p95 = ms_per_call(lambda r: family.predict(r, pred_contrib=True), X, 100)
    answers[folder] = family.predict(X).argmax(1)
    print(f"\n=== {folder}")
    print(f"  size        : binary {size_kb[0]:.0f} KB, family {size_kb[1]:.0f} KB")
    print(f"  model time  : {model_mean:.2f} ms per window (95% under {model_p95:.2f} ms)")
    print(f"  SHAP time   : {shap_mean:.2f} ms per alert  (95% under {shap_p95:.2f} ms)")

same = (answers["models_big"] == answers["models"]).mean() * 100
print(f"\nsmall family model gives the same class as the big one on {same:.1f}% of 2,000 test windows")
