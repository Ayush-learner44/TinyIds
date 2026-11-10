"""Simple rule next to the model: MQTT brute force = many refused logins for one client in a short time.

The broker answers every login with a CONNACK packet; a non-zero return code means "refused".
(The BruteForce class of the model is weak, so this rule catches what the model misses.)
"""
import time
from collections import defaultdict, deque

from scapy.layers.inet import IP, TCP


class BruteForceRule:
    def __init__(self, broker_port, max_fails, seconds):
        self.broker_port = broker_port
        self.max_fails = max_fails
        self.seconds = seconds
        self.refused = defaultdict(deque)          # client IP -> times of refused logins

    def check(self, packet):
        """Look at a packet sent BY the broker. Returns the client IP if it looks like brute force, else None."""
        if TCP not in packet or packet[TCP].sport != self.broker_port:
            return None
        data = bytes(packet[TCP].payload)
        is_refused_login = len(data) >= 4 and data[0] == 0x20 and data[3] != 0     # CONNACK with error code
        if not is_refused_login:
            return None
        client, now = packet[IP].dst, time.time()
        times = self.refused[client]
        times.append(now)
        while times and now - times[0] > self.seconds:
            times.popleft()
        return client if len(times) >= self.max_fails else None

    def count(self, client):
        return len(self.refused[client])
