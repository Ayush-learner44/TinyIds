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

    def close_old(self):
        """Slow senders (like a sensor) never fill a window; flush windows older than the timeout.
        Discard partial windows with < 10 packets to prevent statistical distortion and false alarms."""
        now, closed = time.time(), []
        for sender, w in self.senders.items():
            if w.started and now - w.started > self.timeout:
                if len(w.small) >= self.small_size:
                    closed.append((sender, w.small, self.small_size))
                w.small, w.large, w.started = [], [], None
        return closed
