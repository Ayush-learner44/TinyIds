"""TinyIDS on the Raspberry Pi.

    packet  ->  PacketReader  ->  WindowCollector  ->  FeatureBuilder  ->  Detector  ->  explain (SHAP)  ->  AlertPublisher
                                                                   BruteForceRule  ->  AlertPublisher

Run (needs root to capture packets):   sudo ./venv/bin/python run_tinyids.py --interface wlan0
"""
import argparse
import threading
import time
from collections import defaultdict

from scapy.all import get_if_addr, sniff
from scapy.layers.inet import IP

from tinyids.detector import Detector
from tinyids.features import FeatureBuilder, FlowTable, PacketReader
from tinyids.publisher import AlertPublisher
from tinyids.rules import BruteForceRule
from tinyids.settings import Settings
from tinyids.stats import Stats
from tinyids.windows import WindowCollector


class TinyIDS:
    def __init__(self, settings):
        self.settings = settings
        self.my_ip = get_if_addr(settings.interface)
        self.flows = FlowTable()
        self.reader = PacketReader(self.flows)
        self.windows = WindowCollector(settings.small_window, settings.large_window, settings.window_timeout)
        self.detector = Detector(settings.models_folder)
        self.builder = FeatureBuilder(self.detector.features)
        self.rule = BruteForceRule(settings.broker_port, settings.bruteforce_fails, settings.bruteforce_seconds)
        self.publisher = AlertPublisher(settings)
        self.stats = Stats()
        self.budget = defaultdict(int)          # windows classified this second, per sender
        self.lock = threading.Lock()            # the capture thread and the timer thread share the state above

    # ---------------------------------------------------------------- one window -> maybe an alert
    def handle_window(self, sender, packets, size):
        if self.budget[sender] >= self.settings.max_windows_per_second:
            self.stats.skipped += 1
            return
        self.budget[sender] += 1
        row = self.builder.build(packets)
        detection, model_ms = self.detector.check(sender, row, size)
        self.stats.windows += 1
        self.stats.model_ms.append(model_ms)
        if detection is None or not self.publisher.allowed(sender, detection.attack):
            return
        reasons, shap_ms = self.detector.explain(detection)
        self.stats.shap_ms.append(shap_ms)
        self.stats.alerts += 1
        self.publisher.send_alert({
            "time": time.strftime("%H:%M:%S"), "src": sender, "attack": detection.attack,
            "confidence": detection.confidence, "p_attack": detection.attack_probability, "window": size,
            "top3": reasons, "model_ms": round(model_ms, 3), "shap_ms": round(shap_ms, 3), "source": "model"})

    def handle_bruteforce(self, client):
        if not self.publisher.allowed(client, "BruteForce"):
            return
        self.stats.alerts += 1
        self.publisher.send_alert({
            "time": time.strftime("%H:%M:%S"), "src": client, "attack": "BruteForce", "confidence": 1.0,
            "p_attack": 1.0, "window": 0, "model_ms": 0.0, "shap_ms": 0.0, "source": "rule",
            "top3": [["refused MQTT logins", self.rule.count(client), 0.0],
                     ["within seconds", self.settings.bruteforce_seconds, 0.0],
                     ["rule threshold", self.settings.bruteforce_fails, 0.0]]})

    # ---------------------------------------------------------------- every captured packet
    def on_packet(self, packet):
        with self.lock:
            if IP in packet and packet[IP].src == self.my_ip:          # sent by the Pi: only check for refused logins
                client = self.rule.check(packet)
                if client:
                    self.handle_bruteforce(client)
                return
            info = self.reader.read(packet)
            if info is None:
                return
            self.stats.packets[info.source] += 1
            for sender, packets, size in self.windows.add(info):
                self.handle_window(sender, packets, size)

    # ---------------------------------------------------------------- every second
    def every_second(self):
        while True:
            time.sleep(1)
            with self.lock:
                for sender, packets, size in self.windows.close_old():
                    self.handle_window(sender, packets, size)
                self.flows.forget_old(time.time())
                self.budget.clear()
                message = self.stats.message()
            self.publisher.send_stats(message)

    def start(self):
        meta = self.detector.meta
        self.publisher.send_status({"started": time.strftime("%H:%M:%S"), "features": len(self.detector.features),
                                    "binary": meta["binary"], "family": meta["family"], "gateway": self.my_ip})
        threading.Thread(target=self.every_second, daemon=True).start()
        port = self.settings.broker_port
        # Filter: capture incoming traffic (excluding laptop SSH on port 22) and outgoing MQTT responses
        capture_filter = f"(dst host {self.my_ip} and not port 22) or (src host {self.my_ip} and tcp src port {port})"
        print(f"TinyIDS watching {self.settings.interface} ({self.my_ip}), broker port {port}. Ctrl+C to stop.", flush=True)
        sniff(iface=self.settings.interface, filter=capture_filter, prn=self.on_packet, store=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TinyIDS live detector")
    parser.add_argument("--interface", default="wlan0")
    parser.add_argument("--port", type=int, default=1884, help="port of our Mosquitto")
    args = parser.parse_args()
    TinyIDS(Settings(interface=args.interface, broker_port=args.port)).start()
