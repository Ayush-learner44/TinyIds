"""TinyIDS: the live detector. The same code runs on the Raspberry Pi and in the Docker testbed.

  packet -> PacketReader -> WindowCollector -> FeatureBuilder -> Detector -> AlertFilter -> alert + SHAP -> Responder
  packet sent by the broker -> BruteForceRule -> alert -> Responder
  packet to the broker      -> SensorRegistry (learns which IP is which sensor)

Pi:      sudo ./venv/bin/python run_tinyids.py --interface wlan0 --admin-ip 172.29.2.47
Docker:  python run_tinyids.py --interface eth0 --port 1883 --models /models   (see testbed/docker-compose.yml)
"""
import argparse
import threading
import time
import traceback

from scapy.all import get_if_addr, sniff
from scapy.layers.inet import IP

from tinyids.alert_filter import AlertFilter
from tinyids.detector import Detector
from tinyids.features import FeatureBuilder, FlowTable, PacketReader
from tinyids.publisher import AlertPublisher
from tinyids.response import Firewall, Responder
from tinyids.rules import BruteForceRule, FloodCounter, SensorRegistry
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
        self.detector = Detector(settings)
        self.builder = FeatureBuilder(self.detector.features)
        self.alert_filter = AlertFilter(settings)
        self.bruteforce = BruteForceRule(settings.broker_port, settings.bruteforce_fails, settings.bruteforce_seconds)
        self.floods = FloodCounter(settings.ddos_sources, settings.ddos_seconds)
        self.sensors = SensorRegistry(settings.broker_port)
        self.responder = Responder(settings, Firewall(), self.sensors, self.my_ip)
        self.publisher = AlertPublisher(settings, on_command=self.on_command)
        self.stats = Stats()
        self.budget = {}                        # windows classified this second, per sender
        self.lock = threading.Lock()            # the capture thread and the timer thread share the state above

    # ---------------------------------------------------------------- one window -> maybe an alert
    def handle_window(self, sender, packets, size):
        if not self.has_budget(sender):
            return
        row = self.builder.build(packets)                                   # 1. packets -> 30 features
        detection, model_ms = self.detector.check(sender, row, size)        # 2. binary model, then family model
        self.stats.windows += 1
        self.stats.model_ms.append(model_ms)
        if detection is None:
            self.alert_filter.saw_normal(sender)
            return
        if not self.alert_filter.should_alert(detection):                   # 3. sure enough? not alerted a second ago?
            return
        reasons, shap_ms = self.detector.explain(detection)                 # 4. SHAP top-3 reasons
        self.stats.shap_ms.append(shap_ms)
        self.send_alert(sender, self.attack_name(detection), detection.confidence, size, reasons,
                        detection.model_ms, shap_ms, "model")
        self.responder.respond(sender, detection.attack, detection.confidence)   # 5. block / quarantine / rate-limit

    def attack_name(self, detection):
        """The model says "Flood"; how many senders flood at once tells DoS from DDoS."""
        if detection.attack != "Flood":
            return detection.attack
        kind, senders = self.floods.name(detection.source)
        return f"{kind} flood" if senders == 1 else f"{kind} flood ({senders} senders)"

    def has_budget(self, sender):
        used = self.budget.get(sender, 0)
        if used >= self.settings.max_windows_per_second:
            self.stats.skipped += 1
            return False
        self.budget[sender] = used + 1
        return True

    def handle_bruteforce(self, client):
        if not self.alert_filter.not_too_soon(client, "BruteForce"):
            return
        reasons = [["refused MQTT logins", self.bruteforce.count(client), 0.0],
                   ["within seconds", self.settings.bruteforce_seconds, 0.0],
                   ["rule threshold", self.settings.bruteforce_fails, 0.0]]
        self.send_alert(client, "BruteForce", 1.0, 0, reasons, 0.0, 0.0, "rule")
        self.responder.respond(client, "BruteForce", 1.0)

    def send_alert(self, sender, attack, confidence, window, reasons, model_ms, shap_ms, detected_by):
        self.stats.alerts += 1
        node = self.sensors.name(sender)
        self.publisher.send_alert({
            "time": time.strftime("%H:%M:%S"), "src": sender if not node else f"{sender} ({node})",
            "attack": attack, "confidence": confidence, "window": window, "top3": reasons,
            "model_ms": round(model_ms, 3), "shap_ms": round(shap_ms, 3), "source": detected_by})

    # ---------------------------------------------------------------- every captured packet
    def on_packet(self, packet):
        with self.lock:
            if IP in packet and packet[IP].src == self.my_ip:        # sent by the gateway: only check refused logins
                client = self.bruteforce.check(packet)
                if client:
                    self.handle_bruteforce(client)
                return
            self.sensors.learn(packet)
            info = self.reader.read(packet)
            if info is None:
                return
            self.stats.packets[info.source] += 1
            for sender, packets, size in self.windows.add(info):
                self.handle_window(sender, packets, size)

    def on_command(self, command):
        with self.lock:
            self.responder.handle_command(command)

    # ---------------------------------------------------------------- every second
    def every_second(self):
        while True:
            time.sleep(1)
            try:
                with self.lock:
                    self.windows.drop_old()
                    self.flows.forget_old(time.time())
                    self.responder.release_expired()
                    self.budget.clear()
                    stats, ips_status = self.stats.message(), self.responder.status()
                self.publisher.send_stats(stats)
                self.publisher.send_mitigation_status(ips_status)
            except Exception:
                traceback.print_exc()           # show the full error, but keep the detector running

    def capture_filter(self):
        """Packets TO the gateway (except the admin's own SSH session) + login answers FROM the broker."""
        incoming = f"dst host {self.my_ip}"
        if self.settings.admin_ip:
            incoming += f" and not (src host {self.settings.admin_ip} and tcp port 22)"
        return f"({incoming}) or (src host {self.my_ip} and tcp src port {self.settings.broker_port})"

    def start(self):
        meta = self.detector.meta
        self.publisher.send_status({"started": time.strftime("%H:%M:%S"), "features": len(self.detector.features),
                                    "binary": meta["binary"], "family": meta["family"], "gateway": self.my_ip})
        threading.Thread(target=self.every_second, daemon=True).start()
        print(f"TinyIDS watching {self.settings.interface} ({self.my_ip}), broker port {self.settings.broker_port}, "
              f"IPS {'ON' if self.responder.enabled else 'OFF'}, iptables "
              f"{'available' if self.responder.firewall.available else 'NOT available'}. Ctrl+C to stop.", flush=True)
        sniff(iface=self.settings.interface, filter=self.capture_filter(), prn=self.on_packet, store=False)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TinyIDS live detector")
    parser.add_argument("--interface", default="wlan0")
    parser.add_argument("--port", type=int, default=1884, help="port of the MQTT broker")
    parser.add_argument("--models", default="models", help="folder with binary.txt, family.txt, meta.json")
    parser.add_argument("--admin-ip", default="", help="your laptop: its SSH session is not inspected")
    parser.add_argument("--no-ips", action="store_true", help="detect only, never block")
    parser.add_argument("--shap-rounds", type=int, default=0, help="0 = full model; e.g. 80 = faster, approximate")
    a = parser.parse_args()
    TinyIDS(Settings(interface=a.interface, broker_port=a.port, models_folder=a.models, admin_ip=a.admin_ip,
                     ips_enabled=not a.no_ips, shap_rounds=a.shap_rounds)).start()
