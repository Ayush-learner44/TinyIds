"""Run on the LAPTOP: prepares pi/benchmark/ (test windows + compressed models) for the Pi benchmark.

Takes 20,000 random rows of test.csv (binary labels) and copies the binary models we want to compare:
IDS model (LightGBM, 30 live features), compressed models from model/compress.py (run quant1).
"""
import json
import shutil
from pathlib import Path

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parents[1]                  # the project folder
MODEL = ROOT / "model"
OUT = ROOT / "pi" / "benchmark"
(OUT / "models").mkdir(parents=True, exist_ok=True)

features45 = json.load(open(MODEL / "models_run2" / "meta.json"))["features"]
ranking = pd.read_csv(MODEL / "results_run2" / "rq1_shap_ranking.csv")["feature"].tolist()
top15 = [f for f in ranking if f in features45][:15]
live30 = json.load(open(ROOT / "pi" / "models" / "meta.json"))["features"]
nn = torch.load(MODEL / "models_run2" / "binary_mlp.pt", weights_only=False)

test = pd.read_parquet(MODEL / "cache" / "test.parquet").sample(20_000, random_state=7)
np.savez_compressed(
    OUT / "bench_data.npz",
    X=test[features45].to_numpy(np.float32),
    y=(test["label"] == "BenignTraffic").astype(np.int64).to_numpy(),      # 0 = Attack, 1 = Benign
    features45=np.array(features45), top15=np.array(top15), live30=np.array(live30),
    nn_mean=np.asarray(nn["mu"], np.float32), nn_std=np.asarray(nn["sd"], np.float32))

copies = {
    ROOT / "pi" / "models" / "binary.txt": "ids_lightgbm.txt",
    MODEL / "models_quant1" / "binary_lgbm_pruned.onnx": "lightgbm_pruned.onnx",
    MODEL / "models_quant1" / "binary_rf_pruned.onnx": "randomforest_pruned.onnx",
    MODEL / "models_quant1" / "binary_mlp_fp32.onnx": "mlp_fp32.onnx",
    MODEL / "models_quant1" / "binary_mlp_int8_dynamic.onnx": "mlp_int8.onnx",
    MODEL / "models_quant1" / "binary_cnn_fp32.onnx": "cnn_fp32.onnx",
    MODEL / "models_quant1" / "binary_cnn_int8_static.onnx": "cnn_int8.onnx",
}
for src, name in copies.items():
    shutil.copy(src, OUT / "models" / name)
    print(f"{name:28s} {src.stat().st_size / 1024:8.1f} KB")
print(f"bench_data.npz: {len(test):,} test rows -> {OUT}")
