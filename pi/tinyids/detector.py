"""The machine-learning part: ONE LightGBM model (Benign / Flood / Recon) + TreeSHAP explanations.

1. model   : probability of each class for one window
2. decide  : P(attack) = 1 - P(Benign); below attack_threshold = normal; else the most likely attack class wins
3. explain : top-3 features that pushed the model MOST towards that attack (TreeSHAP, built into LightGBM)
"""
import json
import time
from dataclasses import dataclass, field

from tinyids import no_scipy  # noqa: F401  (must come before lightgbm: saves ~27 MB RAM)
import lightgbm as lgb
import numpy as np


@dataclass
class Detection:
    source: str
    attack: str
    confidence: float
    attack_probability: float
    row: np.ndarray = field(repr=False)
    model_ms: float = 0.0


class Detector:
    def __init__(self, settings):
        folder = settings.models_folder
        self.meta = json.load(open(f"{folder}/meta.json"))
        self.features = self.meta["features"]
        self.model = lgb.Booster(model_file=f"{folder}/{self.meta['model']['file']}")
        self.classes = self.meta["model"]["classes"]             # e.g. ['Benign', 'Flood', 'Recon']
        self.benign = self.classes.index("Benign")
        self.attack_threshold = settings.attack_threshold
        self.shap_rounds = settings.shap_rounds or None          # None = all rounds

    def check(self, source, row):
        """Returns (Detection or None, model time in ms). No alert logic here, only the model."""
        start = time.perf_counter()
        probabilities = self.model.predict(row)[0]
        model_ms = (time.perf_counter() - start) * 1000
        p_attack = 1 - float(probabilities[self.benign])
        if p_attack < self.attack_threshold:
            return None, model_ms
        attack_only = probabilities.copy()
        attack_only[self.benign] = -1                            # the most likely ATTACK class wins
        best = int(np.argmax(attack_only))
        return Detection(source, self.classes[best], round(float(probabilities[best]), 3), round(p_attack, 3),
                         row, model_ms), model_ms

    def explain(self, detection):
        """Top-3 SHAP features for this detection. Returns (list of [feature, value, shap], time in ms)."""
        start = time.perf_counter()
        k, n = len(self.classes), len(self.features)
        contributions = np.asarray(self.model.predict(detection.row, pred_contrib=True,
                                                      num_iteration=self.shap_rounds)[0]).reshape(k, n + 1)
        mine = contributions[self.classes.index(detection.attack)][:n]
        top = np.argsort(-mine)[:3]                              # the 3 features that pushed MOST towards this attack
        reasons = [[self.features[i], round(float(detection.row[0, i]), 3), round(float(mine[i]), 3)] for i in top]
        return reasons, (time.perf_counter() - start) * 1000
