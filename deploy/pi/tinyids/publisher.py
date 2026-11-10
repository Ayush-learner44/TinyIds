"""Send alerts and statistics over MQTT (the dashboard on the laptop subscribes to them).

Topics: ids/alerts (one message per alert), ids/stats (every second), ids/status (once, when TinyIDS starts)
"""
import json
import time

import paho.mqtt.client as mqtt


class AlertPublisher:
    def __init__(self, settings):
        self.gap = settings.alert_gap
        self.last_alert = {}
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="tinyids")
        self.client.username_pw_set(settings.mqtt_user, settings.mqtt_password)
        while True:
            try:
                self.client.connect(settings.broker_host, settings.broker_port, keepalive=30)
                break
            except OSError:
                print("waiting for the broker ...", flush=True)
                time.sleep(1)
        self.client.loop_start()

    def allowed(self, source, attack):
        """At most one alert per second per sender and attack type."""
        key, now = (source, attack), time.time()
        if now - self.last_alert.get(key, 0) < self.gap:
            return False
        self.last_alert[key] = now
        return True

    def send_alert(self, alert):
        self.client.publish("ids/alerts", json.dumps(alert))
        print(f"ALERT {alert['time']}  {alert['src']:>15}  {alert['attack']:<10}  confidence {alert['confidence']:.2f}"
              f"  because {[r[0] for r in alert['top3']]}", flush=True)

    def send_stats(self, stats):
        self.client.publish("ids/stats", json.dumps(stats))

    def send_status(self, status):
        self.client.publish("ids/status", json.dumps(status), retain=True)
