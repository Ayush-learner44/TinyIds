"""AddressWatcher: checks that IP addresses and MAC addresses fit together (a rule, no machine learning).

Every device on the local network has one MAC address (its network card) and normally one IP address.

  ARP spoofing     : an ARP message says "IP X is at MAC B", but we already know IP X is at MAC A
                     -> someone pretends to be another device (man in the middle)
  IP-spoofed flood : ONE MAC sends packets with MANY different source IPs within a few seconds
                     -> the sender fakes its source IP, so blocking the IP is useless: block the MAC
                     (works for any flood: SYN, UDP, ICMP ...)

Why a rule: the model cannot see these. A spoofed flood uses a new IP for every packet, so no sender ever
fills a window; and the dataset's "Spoofing" rows are mostly forwarded normal traffic (only 0.1% ARP).
Limit: MAC addresses do not cross routers, so this works only inside the local network (our case).
The router (and the gateway itself) are trusted: everything from the internet arrives with the router's MAC.
"""
import time
from dataclasses import dataclass, field

from scapy.layers.inet import IP
from scapy.layers.l2 import ARP, Ether


@dataclass
class AddressAlert:
    attack: str             # "ARP spoofing" or "IP spoofing"
    mac: str                # the attacker's MAC (this is what gets blocked)
    ip: str                 # ARP spoofing: the IP it pretends to own; IP spoofing: the last fake IP
    real_mac: str = ""      # ARP spoofing: the MAC that really owns the IP
    reasons: list = field(default_factory=list)


class AddressWatcher:
    def __init__(self, max_ips_per_mac, seconds, trusted_macs):
        self.max_ips_per_mac = max_ips_per_mac
        self.seconds = seconds
        self.trusted = {m.lower() for m in trusted_macs if m}
        self.owner = {}                   # ip -> the MAC we know owns it
        self.ips_of = {}                  # mac -> {source ip: last time seen}

    def remember(self, ip, mac):
        """Learn a correct pair, e.g. from the gateway's ARP table at start."""
        self.owner[ip] = mac.lower()

    def check(self, packet):
        """Returns an AddressAlert, or None if the addresses look fine."""
        if ARP in packet:
            return self.check_arp(packet[ARP])
        if IP in packet and Ether in packet:
            return self.check_ip(packet[Ether].src.lower(), packet[IP].src)
        return None

    def check_arp(self, arp):
        ip, mac = arp.psrc, arp.hwsrc.lower()
        if ip == "0.0.0.0" or mac in self.trusted:
            return None
        known = self.owner.get(ip)
        if known is None:
            self.owner[ip] = mac                   # first time we see this IP: learn it
            return None
        if known == mac:
            return None
        return AddressAlert("ARP spoofing", mac, ip, known,
                            [["IP claimed", ip, 0.0], ["new MAC", mac, 0.0], ["known MAC", known, 0.0]])

    def check_ip(self, mac, ip):
        if mac in self.trusted:
            return None
        now = time.time()
        seen = self.ips_of.setdefault(mac, {})
        seen[ip] = now
        if len(seen) <= self.max_ips_per_mac:
            return None
        for old in [i for i, t in seen.items() if now - t > self.seconds]:
            del seen[old]
        if len(seen) <= self.max_ips_per_mac:
            return None
        count = len(seen)
        seen.clear()                               # start counting again (keeps memory small)
        return AddressAlert("IP spoofing", mac, ip, "",
                            [["source IPs from one MAC", count, 0.0], ["within seconds", self.seconds, 0.0],
                             ["rule threshold", self.max_ips_per_mac, 0.0]])

    @staticmethod
    def read_arp_table(path="/proc/net/arp"):
        """The gateway's own ARP table (Linux): {ip: mac} of devices it already talked to."""
        pairs = {}
        try:
            with open(path) as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                        pairs[parts[0]] = parts[3]
        except OSError:
            pass
        return pairs
