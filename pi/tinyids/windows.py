"""Collect packets into windows, separately for every sender.

One window per sender: 10 packets, as the CICIoT2023 rows (their script makes one row from every ~10 packets).
A window that is not full after 30 s is thrown away; a NodeMCU (1 reading every 2 s) fills one in ~20 s.
"""
import time


class SenderWindow:
    def __init__(self):
        self.packets = []
        self.started = None


class WindowCollector:
    def __init__(self, size, timeout):
        self.size = size
        self.timeout = timeout
        self.senders = {}
        self.max_senders = 2000                         # keeps RAM small during spoofed floods

    def add(self, packet_info):
        """Add one packet. Returns the window if it just became full: list of (sender, packets), else []."""
        w = self.senders.pop(packet_info.source, None) or SenderWindow()
        if len(self.senders) >= self.max_senders:
            del self.senders[next(iter(self.senders))]   # spoofed flood (a new fake sender per packet): forget the quietest
        self.senders[packet_info.source] = w            # most recent sender at the end
        if w.started is None:
            w.started = time.time()
        w.packets.append(packet_info)
        if len(w.packets) < self.size:
            return []
        full = (packet_info.source, w.packets)
        w.packets, w.started = [], None
        return [full]

    def drop_old(self):
        """Throw away windows that are not full after the timeout (and forget idle senders: keeps memory small)."""
        now = time.time()
        self.senders = {sender: w for sender, w in self.senders.items()
                        if not (w.started and now - w.started > self.timeout)}
