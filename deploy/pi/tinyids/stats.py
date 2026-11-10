"""Counters for the dashboard and for the report (published every second on ids/stats)."""
import time
from collections import defaultdict

import numpy as np


class Stats:
    def __init__(self):
        self.packets = defaultdict(int)       # this second, per sender
        self.windows = 0                      # classified windows (total)
        self.alerts = 0
        self.skipped = 0                      # windows skipped because a sender was too fast
        self.model_ms = []
        self.shap_ms = []

    def message(self):
        msg = {"time": time.strftime("%H:%M:%S"), "pps": sum(self.packets.values()), "pps_by_src": dict(self.packets),
               "windows": self.windows, "alerts": self.alerts, "skipped": self.skipped,
               "model_ms": round(float(np.mean(self.model_ms)), 3) if self.model_ms else None,
               "shap_ms": round(float(np.mean(self.shap_ms)), 3) if self.shap_ms else None}
        self.packets.clear()
        self.model_ms, self.shap_ms = self.model_ms[-500:], self.shap_ms[-500:]
        return msg
