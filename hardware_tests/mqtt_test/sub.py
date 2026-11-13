"""Print every message published to topic test/01.

Run:  python sub.py                      broker = localhost (Mosquitto on this laptop)
      python sub.py 172.29.1.135         broker = the Pi (or any IP)
      python sub.py broker.hivemq.com    public broker (needs hotspot, proxy OFF;
                                         the college network blocks MQTT to the internet)
Stop: Ctrl+C
"""
import sys
from datetime import datetime

import paho.mqtt.client as mqtt

TOPIC = "test/01"
BROKER = sys.argv[1] if len(sys.argv) > 1 else "localhost"


def on_connect(client, _userdata, _flags, reason_code, _properties):
    if reason_code == 0:
        print(f"Connected to {BROKER}, listening on '{TOPIC}' ...")
        client.subscribe(TOPIC)
    else:
        print(f"Connect failed: {reason_code}")


def on_message(_client, _userdata, msg):
    now = datetime.now().strftime("%H:%M:%S")
    print(f"{now}  {msg.topic}  {msg.payload.decode()}")


client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message
client.connect(BROKER, 1883, keepalive=60)
try:
    client.loop_forever()
except KeyboardInterrupt:
    print("\nStopped.")
