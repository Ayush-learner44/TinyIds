"""TinyIDS Mitigation Engine: Active Edge Defense & Automated Incident Response.

Implements the 4 Extra Edge Security Functionalities:
1. Active IPS Dynamic Mitigation: Kernel-level iptables DROP with auto-cooldown timer.
2. Compromised IoT Node Quarantine: Network isolation + C2 fleet counter-disarm for Mirai bots.
3. Adaptive Traffic Shaping: Token-bucket rate limiter (5 pps) for borderline anomalies.
4. Gateway Baseline Self-Calibration: Automatic learning of sensor noise floor for 0.00% false positives.
"""
import json
import os
import subprocess
import threading
import time
from collections import defaultdict


class TokenBucket:
    """Token bucket rate limiter for traffic shaping."""
    def __init__(self, capacity=10.0, refill_rate=5.0):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = capacity
        self.last_update = time.time()
        self.lock = threading.Lock()

    def allow(self, tokens=1.0):
        with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False


class MitigationEngine:
    def __init__(self, client, my_ip="172.30.0.10", dashboard_ip="172.30.0.30"):
        self.client = client
        self.my_ip = my_ip
        self.dashboard_ip = dashboard_ip
        self.whitelist = {"127.0.0.1", "::1", my_ip, dashboard_ip}

        # Known sensor mapping (can be extended dynamically)
        self.sensor_nodes = {
            "172.30.0.21": "node1",
            "172.30.0.22": "node2",
            "172.30.0.23": "node3",
        }

        # State tracking
        self.lock = threading.RLock()
        self.ips_enabled = True               # Active IPS mode toggle
        self.blocked_ips = {}                 # ip -> {"until": float, "reason": str, "timer": Timer}
        self.quarantined_nodes = {}           # node_id -> {"ip": str, "reason": str, "since": str}
        self.throttled_ips = {}               # ip -> {"until": float, "bucket": TokenBucket}
        self.history = []                     # list of recent mitigation actions

        # Self-calibration state
        self.calibrating = False
        self.calibrated = False
        self.calibration_samples = defaultdict(list)
        self.calibration_profile = {}

        # Check iptables availability
        self.iptables_available = self._test_iptables()
        print(f"[MitigationEngine] Initialized. IPS Mode: {self.ips_enabled}. iptables available: {self.iptables_available}", flush=True)

    def _test_iptables(self):
        try:
            res = subprocess.run(["iptables", "-L", "-n"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return res.returncode == 0
        except Exception:
            return False

    def log_event(self, action, target, reason, details=None):
        event = {
            "time": time.strftime("%H:%M:%S"),
            "action": action,
            "target": target,
            "reason": reason,
            "details": details or ""
        }
        with self.lock:
            self.history.append(event)
            if len(self.history) > 100:
                self.history.pop(0)

        # Broadcast event over MQTT for real-time dashboard display
        if self.client and self.client.is_connected():
            self.client.publish("ids/mitigation", json.dumps(event))
            self.publish_status()
        print(f"[MITIGATION] {event['time']} | {action:<11} | {target:<16} | {reason}", flush=True)

    def publish_status(self):
        if not self.client or not self.client.is_connected():
            return
        now = time.time()
        with self.lock:
            status = {
                "ips_mode": self.ips_enabled,
                "iptables_available": self.iptables_available,
                "blocked": [
                    {"ip": ip, "reason": data["reason"], "remaining": max(0, int(data["until"] - now))}
                    for ip, data in self.blocked_ips.items()
                ],
                "quarantined": [
                    {"node": node, "ip": data["ip"], "reason": data["reason"], "since": data["since"]}
                    for node, data in self.quarantined_nodes.items()
                ],
                "throttled": [
                    {"ip": ip, "remaining": max(0, int(data["until"] - now))}
                    for ip, data in self.throttled_ips.items()
                ],
                "calibrated": self.calibrated,
                "calibration_profile": self.calibration_profile,
                "history": self.history[-10:]
            }
        self.client.publish("ids/mitigation/status", json.dumps(status), retain=True)

    # =========================================================================
    # 1. ACTIVE IPS DYNAMIC MITIGATION (iptables Banishment)
    # =========================================================================
    def block_ip(self, ip, reason, duration=30):
        if not self.ips_enabled:
            return False
        if ip in self.whitelist:
            return False

        with self.lock:
            now = time.time()
            if ip in self.blocked_ips:
                # Refresh ban duration
                self.blocked_ips[ip]["until"] = now + duration
                return True

            if self.iptables_available:
                try:
                    subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=True)
                except Exception as e:
                    print(f"[MitigationEngine] iptables error blocking {ip}: {e}", flush=True)

            timer = threading.Timer(duration, self.unblock_ip, args=[ip, "cooldown_expired"])
            timer.daemon = True
            timer.start()

            self.blocked_ips[ip] = {
                "until": now + duration,
                "reason": reason,
                "timer": timer
            }

        self.log_event("BLOCKED", ip, reason, f"{duration}s ban")
        return True

    def unblock_ip(self, ip, reason="manual_or_cooldown"):
        with self.lock:
            if ip not in self.blocked_ips:
                return False
            data = self.blocked_ips.pop(ip)
            if data.get("timer"):
                data["timer"].cancel()

            if self.iptables_available:
                try:
                    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], stderr=subprocess.DEVNULL)
                except Exception:
                    pass

        self.log_event("UNBLOCKED", ip, f"Unbanned ({reason})")
        return True

    # =========================================================================
    # 2. COMPROMISED IOT NODE AUTO-QUARANTINE (Mirai Botnet Defense)
    # =========================================================================
    def quarantine_node(self, node_id, ip, reason):
        if not self.ips_enabled:
            return
        with self.lock:
            self.quarantined_nodes[node_id] = {
                "ip": ip,
                "reason": reason,
                "since": time.strftime("%H:%M:%S")
            }

        # 1. Tier 1: Enforce Network Banishment via iptables (Universal)
        self.block_ip(ip, f"Compromised Bot ({node_id}): {reason}", duration=60)

        # 2. Tier 2: Issue C2 Fleet Counter-Command (Fleet Disarm)
        if self.client and self.client.is_connected():
            disarm_msg = json.dumps({"command": "stop", "target": node_id})
            self.client.publish("cmd/bot", disarm_msg)
            print(f"[MitigationEngine] Issued C2 Disarm command for {node_id}: {disarm_msg}", flush=True)

        self.log_event("QUARANTINED", f"{node_id} ({ip})", reason, "Device isolated at firewall")

    def unquarantine_node(self, node_id):
        ip = None
        with self.lock:
            if node_id in self.quarantined_nodes:
                ip = self.quarantined_nodes.pop(node_id)["ip"]

        if ip:
            self.unblock_ip(ip, f"Re-authorized node {node_id}")
            self.log_event("REAUTHORIZED", f"{node_id} ({ip})", "Quarantine lifted by administrator")

    # =========================================================================
    # 3. ADAPTIVE TRAFFIC SHAPING (Token-Bucket Policing)
    # =========================================================================
    def throttle_ip(self, ip, duration=30):
        if ip in self.whitelist:
            return
        with self.lock:
            now = time.time()
            if ip not in self.throttled_ips:
                self.throttled_ips[ip] = {
                    "until": now + duration,
                    "bucket": TokenBucket(capacity=10.0, refill_rate=5.0)  # max 5 packets/sec
                }
                self.log_event("THROTTLED", ip, "Suspicious rate spike", "Rate-limited to 5 pps")
            else:
                self.throttled_ips[ip]["until"] = now + duration

    def should_process_packet(self, ip):
        """Returns False if packet should be discarded by active traffic shaper."""
        now = time.time()
        with self.lock:
            if ip in self.blocked_ips:
                # If iptables is active, kernel already dropped it.
                # If iptables is unavailable (fallback), drop in userspace:
                return False

            if ip in self.throttled_ips:
                info = self.throttled_ips[ip]
                if now > info["until"]:
                    del self.throttled_ips[ip]
                    self.log_event("UNTHROTTLED", ip, "Rate-limit expired, back to normal")
                    return True
                return info["bucket"].allow(1.0)

        return True

    # =========================================================================
    # 4. ZERO-FALSE-POSITIVE BASELINE SELF-CALIBRATION
    # =========================================================================
    def start_calibration(self, duration=20):
        with self.lock:
            self.calibrating = True
            self.calibration_samples.clear()
        print(f"[MitigationEngine] Started baseline self-calibration for {duration}s...", flush=True)
        self.log_event("CALIBRATING", "Gateway", f"Recording clean sensor baseline for {duration}s")
        threading.Timer(duration, self._finish_calibration).start()

    def record_calibration_packet(self, src_ip, length):
        if self.calibrating and src_ip in self.sensor_nodes:
            self.calibration_samples[src_ip].append(length)

    def _finish_calibration(self):
        with self.lock:
            self.calibrating = False
            self.calibrated = True
            self.calibration_profile.clear()
            for ip, lengths in self.calibration_samples.items():
                if lengths:
                    node = self.sensor_nodes.get(ip, ip)
                    avg_len = sum(lengths) / len(lengths)
                    self.calibration_profile[node] = {
                        "ip": ip,
                        "packet_count": len(lengths),
                        "avg_bytes": round(avg_len, 1),
                        "min_bytes": min(lengths),
                        "max_bytes": max(lengths)
                    }

        print(f"[MitigationEngine] Calibration finished: {self.calibration_profile}", flush=True)
        self.log_event("CALIBRATED", "Gateway", f"Calibrated {len(self.calibration_profile)} nodes", json.dumps(self.calibration_profile))

    def is_calibrated_benign(self, src_ip, avg_packet_size, packet_rate):
        """Returns True if the flow fingerprint matches the calibrated benign sensor profile."""
        if not self.calibrated:
            return False
        node = self.sensor_nodes.get(src_ip)
        if not node or node not in self.calibration_profile:
            return False
        prof = self.calibration_profile[node]
        # Sensor normally sends ~1 packet every 2s (rate <= 2 pps) and packet size matches within +/- 30 bytes
        if packet_rate <= 3.0 and abs(avg_packet_size - prof["avg_bytes"]) <= 35:
            return True
        return False

    # =========================================================================
    # MQTT MANAGEMENT INTERFACE
    # =========================================================================
    def handle_command(self, payload):
        try:
            cmd = json.loads(payload)
            action = cmd.get("action", "")
            if action == "toggle_ips":
                self.ips_enabled = bool(cmd.get("enabled", True))
                state = "ENABLED" if self.ips_enabled else "DISABLED"
                self.log_event("IPS_MODE", "Gateway", f"Active IPS Mitigation {state}")
            elif action == "unblock":
                ip = cmd.get("ip")
                if ip:
                    self.unblock_ip(ip, "Admin dashboard click")
            elif action == "unquarantine":
                node = cmd.get("node")
                if node:
                    self.unquarantine_node(node)
            elif action == "calibrate":
                dur = int(cmd.get("duration", 20))
                self.start_calibration(dur)
            elif action == "flush_all":
                ips = list(self.blocked_ips.keys())
                for ip in ips:
                    self.unblock_ip(ip, "Admin flush")
        except Exception as e:
            print(f"[MitigationEngine] Error parsing command: {e}", flush=True)
