"""Command the NodeMCU 'bots' (simulated botnet, like Mirai's command server) through our broker.

python bot_master.py 172.29.1.135 udp_flood --seconds 10
python bot_master.py 172.29.1.135 tcp_flood --seconds 10
python bot_master.py 172.29.1.135 stop

The bots attack only the gateway (fixed in their sketch) and stop by themselves after at most 30 s.
"""
import argparse
import json
import time

import paho.mqtt.client as mqtt


class BotMaster:
    def __init__(self, broker, port, user, password):
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="bot-master")
        self.client.username_pw_set(user, password)
        self.client.on_message = lambda c, u, msg: print(f"  {msg.topic}: {msg.payload.decode()}")
        self.client.connect(broker, port, keepalive=30)
        self.client.subscribe("bot/#")             # bots report what they are doing on bot/<name>/status
        self.client.loop_start()

    def send(self, command, seconds):
        message = json.dumps({"command": command, "seconds": seconds})
        self.client.publish("cmd/bot", message)
        print(f"sent to all bots: {message}")

    def listen(self, seconds):
        time.sleep(seconds)
        self.client.loop_stop()


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="NodeMCU bot master")
    p.add_argument("broker", help="IP of the Pi")
    p.add_argument("command", choices=["udp_flood", "tcp_flood", "stop"])
    p.add_argument("--seconds", type=int, default=10)
    p.add_argument("--port", type=int, default=1884)
    p.add_argument("--user", default="tinyids")
    p.add_argument("--password", default="tinyids123")
    a = p.parse_args()
    master = BotMaster(a.broker, a.port, a.user, a.password)
    master.send(a.command, a.seconds)
    master.listen(a.seconds + 4 if a.command != "stop" else 2)
