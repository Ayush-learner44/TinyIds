"""Port scan (like nmap -sS): send one SYN to each port; a SYN-ACK answer means the port is open.

python port_scan.py 172.29.1.135                  (ports 1-1024)
python port_scan.py 172.29.1.135 --last 200
"""
import argparse

from scapy.all import sr
from scapy.layers.inet import IP, TCP


class PortScanner:
    def __init__(self, target, first_port, last_port):
        self.target = target
        self.ports = (first_port, last_port)

    def run(self):
        print(f"port scan: {self.target} ports {self.ports[0]}-{self.ports[1]}")
        probes = IP(dst=self.target) / TCP(dport=self.ports, flags="S")
        answered, _ = sr(probes, timeout=2, inter=0.001, verbose=False)
        open_ports = sorted(sent[TCP].dport for sent, reply in answered
                            if reply.haslayer(TCP) and reply[TCP].flags == "SA")
        print(f"done: {len(answered)} answers, open ports: {open_ports}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="SYN port scan")
    p.add_argument("target")
    p.add_argument("--first", type=int, default=1)
    p.add_argument("--last", type=int, default=1024)
    a = p.parse_args()
    PortScanner(a.target, a.first, a.last).run()
