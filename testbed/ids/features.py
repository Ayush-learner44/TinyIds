"""Live feature extractor: packets -> the CICIoT2023 features the IDS models use (see model/make_ids_models.py).

Per packet we compute values (flags, protocol, size, ...) plus per-flow running values (flow duration, cumulative header
bytes, packet rate); a window of packets is then summarised by averaging, like the CICIoT2023 authors did.
Sizes include the 14-byte Ethernet header (a bare SYN = 54 bytes, as in the dataset).
"""
import numpy as np
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether, LLC

APP_PORTS = {"HTTP": {80, 8080}, "HTTPS": {443}, "DNS": {53}, "Telnet": {23}, "SMTP": {25, 587},
             "SSH": {22}, "IRC": {6667}}
FLAG_BITS = {"fin_flag_number": 0x01, "syn_flag_number": 0x02, "rst_flag_number": 0x04, "psh_flag_number": 0x08,
             "ack_flag_number": 0x10, "ece_flag_number": 0x40, "cwr_flag_number": 0x80}
MEAN_FEATURES = (["flow_duration", "Header_Length", "Protocol Type", "Rate"] + list(FLAG_BITS) + list(APP_PORTS)
                 + ["TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC"])
SIZE_FEATURES = ["Min", "Max", "AVG", "Std", "Tot size"]
KNOWN_FEATURES = set(MEAN_FEATURES) | set(SIZE_FEATURES)


class FlowTable:
    """Running state per flow (both directions of a connection share one entry)."""

    def __init__(self):
        self.flows = {}

    def update(self, key, ts, header_len):
        st = self.flows.get(key)
        if st is None:
            st = self.flows[key] = [ts, 0, 0, ts]          # first seen, packets, header bytes, last seen
        st[1] += 1
        st[2] += header_len
        st[3] = ts
        dur = ts - st[0]
        return dur, st[2], (st[1] / dur if dur > 0 else 0.0)

    def expire(self, now, idle=60):
        for k in [k for k, st in list(self.flows.items()) if now - st[3] > idle]:
            self.flows.pop(k, None)


def packet_values(pkt, flows):
    """Return (source address, timestamp, dict of per-packet values) or None for packets we cannot use."""
    ts = float(pkt.time)
    v = dict.fromkeys(MEAN_FEATURES, 0.0)
    v["size"] = float(len(pkt))
    hdr = 14 if Ether in pkt else 0
    if LLC in pkt:
        v["LLC"] = 1.0
    if ARP in pkt:
        a = pkt[ARP]
        v["ARP"] = 1.0
        src, key, hdr = a.psrc, ("arp", a.psrc, a.pdst), hdr + 28
    elif IP in pkt:
        ip = pkt[IP]
        src = ip.src
        v["IPv"] = 1.0
        v["Protocol Type"] = float(ip.proto)
        hdr += (ip.ihl or 5) * 4
        sport = dport = 0
        if TCP in pkt:
            t = pkt[TCP]
            v["TCP"] = 1.0
            hdr += (t.dataofs or 5) * 4
            fl = int(t.flags)
            for name, bit in FLAG_BITS.items():
                v[name] = 1.0 if fl & bit else 0.0
            sport, dport = t.sport, t.dport
        elif UDP in pkt:
            u = pkt[UDP]
            v["UDP"] = 1.0
            hdr += 8
            sport, dport = u.sport, u.dport
            if {sport, dport} & {67, 68}:
                v["DHCP"] = 1.0
        elif ICMP in pkt:
            v["ICMP"] = 1.0
            hdr += 8
        for name, ports in APP_PORTS.items():
            if sport in ports or dport in ports:
                v[name] = 1.0
        a, b = (ip.src, sport), (ip.dst, dport)
        key = (min(a, b), max(a, b), ip.proto)
    else:
        return None
    v["flow_duration"], v["Header_Length"], v["Rate"] = flows.update(key, ts, hdr)
    return src, ts, v


def window_features(values, order):
    """Summarise a window (list of per-packet dicts) into one feature vector in the model's feature order."""
    out = {f: float(np.mean([v[f] for v in values])) for f in MEAN_FEATURES}
    sizes = np.array([v["size"] for v in values])
    out.update({"Min": sizes.min(), "Max": sizes.max(), "AVG": sizes.mean(), "Std": sizes.std(), "Tot size": sizes.mean()})
    return np.array([out[f] for f in order], dtype=np.float32)
