"""Decides whether a detection becomes an alert (fewer false alarms, no alert spam).

Two simple ideas:
- hysteresis: a sure detection (confidence >= sure_threshold) alerts at once; an unsure one must be seen
  in several windows in a row from the same sender before it alerts
- alert gap: at most one alert per second per sender and attack type
"""
import time
from collections import defaultdict


class AlertFilter:
    def __init__(self, settings):
        self.sure = settings.sure_threshold
        self.needed = settings.unsure_windows_needed
        self.gap = settings.alert_gap
        self.in_a_row = defaultdict(int)       # sender -> flagged windows in a row
        self.last_alert = {}                   # (sender, attack) -> time of last alert

    def saw_normal(self, sender):
        self.in_a_row[sender] = 0

    def should_alert(self, detection):
        sender = detection.source
        self.in_a_row[sender] += 1
        if detection.confidence < self.sure and self.in_a_row[sender] < self.needed:
            return False
        return self.not_too_soon(sender, detection.attack)

    def not_too_soon(self, sender, attack):
        key, now = (sender, attack), time.time()
        if now - self.last_alert.get(key, 0) < self.gap:
            return False
        self.last_alert[key] = now
        return True
