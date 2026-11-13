"""Merge the fresh results into ONE table: model/fresh/RESULTS.md (+ fresh_all.csv).

Inputs (written by train_fresh.py):  results/fresh_trees.csv (RF + LightGBM), results/fresh_lgbm34.csv
(34-class LightGBM re-run with a gentler learning rate, replaces the first 34-class LightGBM rows),
results/fresh_nets.csv (MLP + 1D-CNN). The old run (model/results_run2/results_summary.csv) is shown next to it.
"""
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
R = HERE / "results"

trees = pd.read_csv(R / "fresh_trees.csv")
if (R / "fresh_lgbm34.csv").exists():
    trees = trees[~((trees.task == "34class") & (trees.model == "lgbm"))]
    trees = pd.concat([trees, pd.read_csv(R / "fresh_lgbm34.csv")])
parts = [trees] + ([pd.read_csv(R / "fresh_nets.csv")] if (R / "fresh_nets.csv").exists() else [])
table = pd.concat(parts)
table = table[table.variant != "fp32 on same 50k"]          # helper row, only used for the INT8 comparison below
order = {"binary": 0, "8class": 1, "34class": 2}
mod = {"rf": 0, "lgbm": 1, "mlp": 2, "cnn": 3}
table = table.sort_values(by=["task", "model"], key=lambda c: c.map(order) if c.name == "task" else c.map(mod))
table.to_csv(R / "fresh_all.csv", index=False)

old = pd.read_csv(HERE.parent / "results_run2" / "results_summary.csv")
old = old.set_index(["task", "model"])["macro_f1"]

lines = ["# Fresh training run, 13 Nov 2026 (`model/fresh/train_fresh.py`)", "",
         "20 % stratified sample of train.csv (1.1 M rows), early stopping on 20 % of validation.csv, scored on the FULL "
         "test.csv (1.18 M rows; INT8 rows on 50,000 random test rows scored one row at a time). 45 features (no IAT).",
         "Size = bytes of the saved model. Latency = ONE row at a time on the laptop CPU (Pi is ~3-4x slower).",
         "\"old\" = macro-F1 of the previous run (results_run2, 3 epochs for the nets).", ""]
for task in ("binary", "8class", "34class"):
    t = table[table.task == task]
    if t.empty:
        continue
    lines += [f"## {task}", "", "| model | version | accuracy | macro-F1 | old macro-F1 | benign false alarms | size (KB) | latency (ms) |",
              "|---|---|---|---|---|---|---|---|"]
    for _, r in t.iterrows():
        o = old.get((task, r.model), float("nan")) if r.variant.startswith("full") else float("nan")
        lines.append(f"| {r.model} | {r.variant} | {r.accuracy:.4f} | **{r.macro_f1:.4f}** | "
                     f"{'' if pd.isna(o) else f'{o:.4f}'} | {r.benign_false_alarm:.4f} | {r.size_kb:,.1f} | {r.latency_ms:.3f} |")
    lines.append("")
(HERE / "RESULTS.md").write_text("\n".join(lines), encoding="utf-8")
print("\n".join(lines))
