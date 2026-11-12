"""Collect packets into windows, separately for every sender.

Every sender has two windows at the same time: a small one (10 packets) and a large one (100 packets),
because the CICIoT2023 rows were made from 10-packet windows (most traffic) and 100-packet windows (floods).
"""
import time


class SenderWindows:
    def __init__(self):
        self.small = []
        self.large = []
        self.started = None


class WindowCollector:
    def __init__(self, small_size, large_size, timeout):
        self.small_size = small_size
        self.large_size = large_size
        self.timeout = timeout
        self.senders = {}

    def add(self, packet_info):
        """Add one packet. Returns the windows that just became full: list of (sender, packets, size)."""
        w = self.senders.setdefault(packet_info.source, SenderWindows())
        if w.started is None:
            w.started = time.time()
        w.small.append(packet_info)
        w.large.append(packet_info)
        full = []
        if len(w.small) >= self.small_size:
            full.append((packet_info.source, w.small, self.small_size))
            w.small, w.started = [], time.time()
        if len(w.large) >= self.large_size:
            full.append((packet_info.source, w.large, self.large_size))
            w.large = []
        return full

    def drop_old(self):
        """Throw away windows that are not full after the timeout.

        A sensor sends 1 packet every 2 s, so its window never fills. Classifying a 2-packet window gives
        nonsense features and false alarms, so it is dropped. KNOWN LIMITATION: senders slower than
        ~2 packets/s are never classified by the model (the brute-force rule still sees them).
        Fix planned: retrain with benign windows recorded from our own testbed."""
        now = time.time()
        for w in self.senders.values():
            if w.started and now - w.started > self.timeout:
                w.small, w.large, w.started = [], [], None
