"""What the gateway does after an alert (IPS = Intrusion Prevention System).

Firewall  : adds and removes Linux iptables rules, so the KERNEL really drops the packets
Responder : decides the action for an alert
            sure attack from an outside machine -> block       (drop all its packets)
            sure attack from one of OUR sensors  -> quarantine  (same, but longer: the node is compromised)
            unsure attack                        -> rate-limit  (drop only what is above N packets/s)
Every action ends by itself after a few seconds (checked once per second by release_expired).
"""
import subprocess
import time


class Firewall:
    def __init__(self):
        self.available = self.run(["iptables", "-L", "INPUT", "-n"])

    @staticmethod
    def run(command):
        try:
            return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        except FileNotFoundError:
            return False

    def add(self, rule):
        return self.available and self.run(["iptables", "-I", "INPUT"] + rule)

    def remove(self, rule):
        return self.available and self.run(["iptables", "-D", "INPUT"] + rule)

    @staticmethod
    def drop_rule(ip):
        return ["-s", ip, "-j", "DROP"]

    @staticmethod
    def limit_rule(ip, per_second):
        name = "t" + "".join(f"{int(part):03d}" for part in ip.split("."))     # iptables allows <= 15 characters
        return ["-s", ip, "-m", "hashlimit", "--hashlimit-name", name, "--hashlimit-above", f"{per_second}/sec",
                "--hashlimit-burst", str(per_second * 2), "-j", "DROP"]


class Responder:
    def __init__(self, settings, firewall, sensors, gateway_ip):
        self.settings = settings
        self.firewall = firewall
        self.sensors = sensors
        self.enabled = settings.ips_enabled
        self.never_block = {gateway_ip, settings.admin_ip} - {""}
        self.active = {}            # ip -> {"action", "until", "reason", "node", "rule"}
        self.history = []

    # ---------------------------------------------------------------- deciding
    def respond(self, ip, attack, confidence):
        if not self.enabled or ip in self.never_block:
            return
        node = self.sensors.name(ip)
        s = self.settings
        if confidence >= s.sure_threshold:
            action = "quarantine" if node else "block"
            seconds = s.quarantine_seconds if node else s.block_seconds
            rule = Firewall.drop_rule(ip)
        else:
            action, seconds, rule = "rate_limit", s.rate_limit_seconds, Firewall.limit_rule(ip, s.rate_limit_per_second)

        current = self.active.get(ip)
        if current and not (current["action"] == "rate_limit" and action != "rate_limit"):
            return                                          # already handled (a rate limit may still become a block)
        if current:
            self.release(ip, "stronger action needed")
        enforced = self.firewall.add(rule)
        self.active[ip] = {"action": action, "until": time.time() + seconds, "node": node, "rule": rule,
                           "reason": f"{attack} ({confidence:.2f})"}
        self.log(action.upper(), ip if not node else f"{node} ({ip})",
                 f"{attack}, confidence {confidence:.2f}, {seconds} s" + ("" if enforced else ", NOT enforced: no iptables"))

    # ---------------------------------------------------------------- undoing
    def release(self, ip, why):
        entry = self.active.pop(ip, None)
        if entry:
            self.firewall.remove(entry["rule"])
            self.log("RELEASED", ip, why)

    def release_expired(self):
        now = time.time()
        for ip in [ip for ip, e in self.active.items() if now > e["until"]]:
            self.release(ip, "time is up")

    def release_all(self, why):
        for ip in list(self.active):
            self.release(ip, why)

    # ---------------------------------------------------------------- dashboard
    def handle_command(self, command):
        """Commands from the dashboard on topic cmd/mitigation."""
        action = command.get("action")
        if action == "toggle_ips":
            self.enabled = bool(command.get("enabled", True))
            self.log("IPS_MODE", "gateway", "ON (detect + block)" if self.enabled else "OFF (detect only)")
            if not self.enabled:
                self.release_all("IPS switched off")
        elif action == "unblock" and command.get("ip"):
            self.release(command["ip"], "released from the dashboard")
        elif action == "flush_all":
            self.release_all("all released from the dashboard")

    def log(self, action, target, details):
        self.history.append({"time": time.strftime("%H:%M:%S"), "action": action, "target": target, "details": details})
        self.history = self.history[-50:]
        print(f"IPS {action:<10} {target}  {details}", flush=True)

    def status(self):
        now = time.time()

        def rows(kind):
            return [{"ip": ip, "node": e["node"], "reason": e["reason"], "remaining": max(0, int(e["until"] - now))}
                    for ip, e in self.active.items() if e["action"] == kind]

        return {"ips_mode": self.enabled, "iptables_available": self.firewall.available,
                "blocked": rows("block"), "quarantined": rows("quarantine"), "rate_limited": rows("rate_limit"),
                "history": self.history[-10:]}
