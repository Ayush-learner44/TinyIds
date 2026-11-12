"""Talks to the dashboard over MQTT.

Sends:    ids/alerts (one message per alert), ids/stats (every second), ids/status (once, at start),
          ids/mitigation/status (every second: IPS on/off, blocked / quarantined / rate-limited senders)
Receives: cmd/mitigation (buttons on the dashboard: IPS on/off, unblock, flush)
"""
import json
import time

import paho.mqtt.client as mqtt


class AlertPublisher:
    def __init__(self, settings, on_command=None):
        self.on_command = on_command
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="tinyids")
        self.client.username_pw_set(settings.mqtt_user, settings.mqtt_password)
        self.client.on_connect = lambda c, u, f, code, p: c.subscribe("cmd/mitigation")
        self.client.on_message = self.received
        while True:
            try:
                self.client.connect(settings.broker_host, settings.broker_port, keepalive=30)
                break
            except OSError:
                print("waiting for the broker ...", flush=True)
                time.sleep(1)
        self.client.loop_start()

    def received(self, _client, _userdata, message):
        if self.on_command:
            try:
                self.on_command(json.loads(message.payload))
            except ValueError:
                print(f"ignored a command that is not JSON: {message.payload!r}", flush=True)

    def send_alert(self, alert):
        self.client.publish("ids/alerts", json.dumps(alert))
        print(f"ALERT {alert['time']}  {alert['src']:>15}  {alert['attack']:<10}  confidence {alert['confidence']:.2f}"
              f"  because {[r[0] for r in alert['top3']]}", flush=True)

    def send_stats(self, stats):
        self.client.publish("ids/stats", json.dumps(stats))

    def send_mitigation_status(self, status):
        self.client.publish("ids/mitigation/status", json.dumps(status), retain=True)

    def send_status(self, status):
        self.client.publish("ids/status", json.dumps(status), retain=True)
