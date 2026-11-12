"""Simple rules next to the model (no machine learning).

BruteForceRule : many refused MQTT logins from one client in a short time = brute force
FloodCounter   : one sender flooding = DoS, several senders flooding at the same time = DDoS
SensorRegistry : learns which IP is which sensor, from the MQTT messages the sensors publish (sensors/<name>)
"""
import time
from collections import defaultdict, deque

from scapy.layers.inet import IP, TCP


class BruteForceRule:
    """The broker answers every login with a CONNACK packet; a non-zero return code means "refused"."""

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
        is_refused_login = len(data) >= 4 and data[0] == 0x20 and data[3] != 0     # CONNACK with an error code
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


class FloodCounter:
    """The model only says "Flood". DDoS means MANY attackers at once, so we count the flooding senders."""

    def __init__(self, ddos_sources, seconds):
        self.ddos_sources = ddos_sources
        self.seconds = seconds
        self.last_seen = {}                        # flooding sender -> last time it was flagged

    def name(self, sender):
        """Call when `sender` is flagged as Flood. Returns ("DoS" or "DDoS", number of flooding senders)."""
        now = time.time()
        self.last_seen[sender] = now
        for s in [s for s, t in self.last_seen.items() if now - t > self.seconds]:
            del self.last_seen[s]
        flooding = len(self.last_seen)
        return ("DDoS" if flooding >= self.ddos_sources else "DoS"), flooding


class SensorRegistry:
    """Learns sensor IPs from MQTT PUBLISH packets to topic sensors/<name> (no hard-coded IP addresses)."""

    def __init__(self, broker_port):
        self.broker_port = broker_port
        self.name_of = {}                          # IP -> sensor name

    def learn(self, packet):
        if TCP not in packet or packet[TCP].dport != self.broker_port:
            return
        data = bytes(packet[TCP].payload)
        if len(data) < 5 or data[0] & 0xF0 != 0x30:          # 0x3_ = MQTT PUBLISH
            return
        i = 1
        while i < 5 and data[i] & 0x80:                      # skip the "remaining length" field (1-4 bytes)
            i += 1
        i += 1
        if i + 2 > len(data):
            return
        topic_length = (data[i] << 8) | data[i + 1]
        topic = data[i + 2:i + 2 + topic_length].decode(errors="ignore")
        if topic.startswith("sensors/"):
            self.name_of[packet[IP].src] = topic.split("/")[1]

    def name(self, ip):
        return self.name_of.get(ip)
