"""Turn packets into the CICIoT2023 features the models were trained on.

PacketReader  : one packet  -> PacketInfo (sender, time, values like flags, protocol, size)
FlowTable     : remembers every connection, for flow duration / header bytes / rate
FeatureBuilder: a window of PacketInfo -> one feature row (averages, like the dataset authors did)
"""
from dataclasses import dataclass

import numpy as np
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether, LLC

APP_PORTS = {"HTTP": {80, 8080}, "HTTPS": {443}, "DNS": {53}, "Telnet": {23}, "SMTP": {25, 587},
             "SSH": {22}, "IRC": {6667}}
TCP_FLAGS = {"fin_flag_number": 0x01, "syn_flag_number": 0x02, "rst_flag_number": 0x04, "psh_flag_number": 0x08,
             "ack_flag_number": 0x10, "ece_flag_number": 0x40, "cwr_flag_number": 0x80}
AVERAGED = (["flow_duration", "Header_Length", "Protocol Type", "Rate"] + list(TCP_FLAGS) + list(APP_PORTS)
            + ["TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC"])
SIZE_STATS = ["Min", "Max", "AVG", "Std", "Tot size"]
ALL_FEATURES = set(AVERAGED) | set(SIZE_STATS)


@dataclass
class PacketInfo:
    source: str
    time: float
    values: dict


class FlowTable:
    """Running numbers per connection (both directions share one entry).

    At most `max_flows` connections are remembered (keeps RAM small during floods, where every packet is a
    "new connection"). When full, the connection that was quiet the longest is forgotten first, so the
    sensors (a packet every 2 s) are never the ones dropped."""

    def __init__(self, max_flows=2000):
        self.max_flows = max_flows
        self.flows = {}                                 # oldest activity first (Python dicts keep order)

    def update(self, key, now, header_bytes):
        flow = self.flows.pop(key, None)                # take it out ...
        if flow is None:
            flow = {"first": now, "packets": 0, "header_bytes": 0, "last": now}
            if len(self.flows) >= self.max_flows:
                del self.flows[next(iter(self.flows))]  # forget the connection quiet the longest
        self.flows[key] = flow                          # ... and put it back at the end = most recent
        flow["packets"] += 1
        flow["header_bytes"] += header_bytes
        flow["last"] = now
        duration = now - flow["first"]
        rate = flow["packets"] / duration if duration > 0 else 0.0
        return duration, flow["header_bytes"], rate

    def forget_old(self, now, idle_seconds=60):
        for key in [k for k, f in self.flows.items() if now - f["last"] > idle_seconds]:
            del self.flows[key]


class PacketReader:
    """Reads one packet. Sizes include the 14-byte Ethernet header, as in the dataset (a bare SYN = 54 bytes)."""

    def __init__(self, flows):
        self.flows = flows

    def read(self, packet):
        values = dict.fromkeys(AVERAGED, 0.0)
        values["size"] = float(len(packet))
        header = 14 if Ether in packet else 0
        if LLC in packet:
            values["LLC"] = 1.0

        if ARP in packet:
            arp = packet[ARP]
            values["ARP"] = 1.0
            source, key, header = arp.psrc, ("arp", arp.psrc, arp.pdst), header + 28
        elif IP in packet:
            ip = packet[IP]
            source = ip.src
            values["IPv"] = 1.0
            values["Protocol Type"] = float(ip.proto)
            header += (ip.ihl or 5) * 4
            sport = dport = 0
            if TCP in packet:
                tcp = packet[TCP]
                values["TCP"] = 1.0
                header += (tcp.dataofs or 5) * 4
                for name, bit in TCP_FLAGS.items():
                    values[name] = 1.0 if int(tcp.flags) & bit else 0.0
                sport, dport = tcp.sport, tcp.dport
            elif UDP in packet:
                udp = packet[UDP]
                values["UDP"] = 1.0
                header += 8
                sport, dport = udp.sport, udp.dport
                if {sport, dport} & {67, 68}:
                    values["DHCP"] = 1.0
            elif ICMP in packet:
                values["ICMP"] = 1.0
                header += 8
            for name, ports in APP_PORTS.items():
                if sport in ports or dport in ports:
                    values[name] = 1.0
            side_a, side_b = (ip.src, sport), (ip.dst, dport)
            key = (min(side_a, side_b), max(side_a, side_b), ip.proto)
        else:
            return None

        now = float(packet.time)
        values["flow_duration"], values["Header_Length"], values["Rate"] = self.flows.update(key, now, header)
        return PacketInfo(source, now, values)


class FeatureBuilder:
    """Summarises a window of packets into one row, in the order the model expects."""

    def __init__(self, feature_order):
        missing = [f for f in feature_order if f not in ALL_FEATURES]
        if missing:
            raise ValueError(f"the model needs features we cannot compute: {missing}")
        self.order = feature_order

    def build(self, packets):
        row = {name: float(np.mean([p.values[name] for p in packets])) for name in AVERAGED}
        sizes = np.array([p.values["size"] for p in packets])
        row.update({"Min": sizes.min(), "Max": sizes.max(), "AVG": sizes.mean(), "Std": sizes.std(),
                    "Tot size": sizes.mean()})
        return np.array([[row[name] for name in self.order]], dtype=np.float32)
