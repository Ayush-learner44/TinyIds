"""The machine-learning part: two LightGBM models + TreeSHAP explanations.

1. binary model : attack or normal?
2. family model : which kind of attack? (Flood, Mirai, Recon, Spoofing, Web, BruteForce)
3. explain      : top-3 features that pushed the decision (TreeSHAP, built into LightGBM: pred_contrib=True)
"""
import json
import time
from dataclasses import dataclass, field

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
    def __init__(self, models_folder):
        self.meta = json.load(open(f"{models_folder}/meta.json"))
        self.features = self.meta["features"]
        self.binary = lgb.Booster(model_file=f"{models_folder}/{self.meta['binary']['file']}")
        self.family = lgb.Booster(model_file=f"{models_folder}/{self.meta['family']['file']}")
        self.binary_classes = self.meta["binary"]["classes"]     # ['Attack', 'Benign']
        self.family_classes = self.meta["family"]["classes"]
        self.window_of = self.meta["windows"]                    # which window size each family comes from
        self.consecutive = {}                                    # source -> consecutive flagged windows

    def check(self, source, row, window_size):
        """Returns (Detection or None, model time in ms)."""
        start = time.perf_counter()
        p_class1 = float(self.binary.predict(row)[0])
        p_attack = 1 - p_class1 if self.binary_classes[1] == "Benign" else p_class1
        if p_attack < 0.70:
            self.consecutive[source] = 0
            return None, (time.perf_counter() - start) * 1000
        probabilities = self.family.predict(row)[0]
        best = int(np.argmax(probabilities))
        attack = self.family_classes[best]
        model_ms = (time.perf_counter() - start) * 1000
        if attack == "Benign" or self.window_of.get(attack) != window_size:
            self.consecutive[source] = 0
            return None, model_ms          # the two models disagree, or the attack came from the wrong window size

        conf = float(probabilities[best])
        if conf < 0.90:
            self.consecutive[source] = self.consecutive.get(source, 0) + 1
            if self.consecutive[source] < 2:
                return None, model_ms
        else:
            self.consecutive[source] = 2

        return Detection(source, attack, round(conf, 3), round(p_attack, 3),
                         window_size, row, model_ms), model_ms

    def explain(self, detection):
        """Top-3 SHAP features for this detection. Returns (list of [feature, value, shap], time in ms)."""
        start = time.perf_counter()
        k, n = len(self.family_classes), len(self.features)
        # Fast TreeSHAP: limit to top 80 boosting trees (drops SHAP time from ~96ms to ~22ms on Pi, keeps top-3 ranking)
        contributions = np.asarray(self.family.predict(detection.row, pred_contrib=True, num_iteration=80)[0]).reshape(k, n + 1)
        mine = contributions[self.family_classes.index(detection.attack)][:n]
        top = np.argsort(-np.abs(mine))[:3]
        reasons = [[self.features[i], round(float(detection.row[0, i]), 3), round(float(mine[i]), 3)] for i in top]
        return reasons, (time.perf_counter() - start) * 1000
