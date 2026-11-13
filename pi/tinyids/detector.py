"""The machine-learning part: two LightGBM models + TreeSHAP explanations.

1. binary model : attack or normal?
2. family model : which kind of attack? (Flood, Mirai, Recon, Spoofing, Web, BruteForce)
3. explain      : top-3 features that pushed the decision (TreeSHAP, built into LightGBM: pred_contrib=True)
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
    window_size: int
    row: np.ndarray = field(repr=False)
    model_ms: float = 0.0


class Detector:
    def __init__(self, settings):
        folder = settings.models_folder
        self.meta = json.load(open(f"{folder}/meta.json"))
        self.features = self.meta["features"]
        self.binary = lgb.Booster(model_file=f"{folder}/{self.meta['binary']['file']}")
        self.family = lgb.Booster(model_file=f"{folder}/{self.meta['family']['file']}")
        self.binary_classes = self.meta["binary"]["classes"]     # ['Attack', 'Benign']
        self.family_classes = self.meta["family"]["classes"]
        self.window_of = self.meta["windows"]                    # which window size each family comes from
        self.attack_threshold = settings.attack_threshold
        self.shap_rounds = settings.shap_rounds or None          # None = all rounds

    def check(self, source, row, window_size):
        """Returns (Detection or None, model time in ms). No alert logic here, only the two models."""
        start = time.perf_counter()
        p_class1 = float(self.binary.predict(row)[0])
        p_attack = 1 - p_class1 if self.binary_classes[1] == "Benign" else p_class1
        if p_attack < self.attack_threshold:
            return None, (time.perf_counter() - start) * 1000
        probabilities = self.family.predict(row)[0]
        best = int(np.argmax(probabilities))                     # the most likely family wins
        attack = self.family_classes[best]
        model_ms = (time.perf_counter() - start) * 1000
        if attack == "Benign" or self.window_of.get(attack) != window_size:
            return None, model_ms          # the two models disagree, or the attack came from the wrong window size
        return Detection(source, attack, round(float(probabilities[best]), 3), round(p_attack, 3),
                         window_size, row, model_ms), model_ms

    def explain(self, detection):
        """Top-3 SHAP features for this detection. Returns (list of [feature, value, shap], time in ms)."""
        start = time.perf_counter()
        k, n = len(self.family_classes), len(self.features)
        contributions = np.asarray(self.family.predict(detection.row, pred_contrib=True,
                                                       num_iteration=self.shap_rounds)[0]).reshape(k, n + 1)
        mine = contributions[self.family_classes.index(detection.attack)][:n]
        top = np.argsort(-np.abs(mine))[:3]
        reasons = [[self.features[i], round(float(detection.row[0, i]), 3), round(float(mine[i]), 3)] for i in top]
        return reasons, (time.perf_counter() - start) * 1000
