"""All TinyIDS settings in one place. Every number the detector uses lives here."""
from dataclasses import dataclass


@dataclass
class Settings:
    # ---- where to listen
    interface: str = "wlan0"            # network card to watch (Docker testbed: eth0)
    broker_host: str = "127.0.0.1"      # the MQTT broker runs on the gateway itself
    broker_port: int = 1884             # Pi: our own broker on 1884 (lab broker stays on 1883); Docker: 1883
    mqtt_user: str = "tinyids"
    mqtt_password: str = "tinyids123"
    models_folder: str = "models"
    admin_ip: str = ""                  # your laptop: its SSH session to the gateway is not inspected ("" = inspect everything)

    # ---- packet windows (as in CICIoT2023)
    small_window: int = 10              # Benign / Recon / Spoofing / Web / BruteForce rows were made from 10 packets
    large_window: int = 100             # Flood / Mirai rows were made from 100 packets
    window_timeout: float = 5.0         # a window that is not full after this many seconds is thrown away
    max_windows_per_second: int = 25   # per sender; extra windows are skipped so the IDS never falls behind

    # ---- decision
    attack_threshold: float = 0.70      # binary model: P(attack) below this = normal traffic
    sure_threshold: float = 0.90        # family model: confidence at or above this = alert at once
    unsure_windows_needed: int = 2      # below sure_threshold the same sender must be flagged this many windows in a row
    alert_gap: float = 1.0              # at most one alert per second per sender and attack type
    shap_rounds: int = 0                # 0 = explain the full model; e.g. 80 = only the first 80 rounds (faster, approximate)

    # ---- rules (not machine learning)
    bruteforce_fails: int = 5           # this many refused MQTT logins ...
    bruteforce_seconds: float = 10.0    # ... within this many seconds = brute force
    ddos_sources: int = 3               # this many different senders flooding ...
    ddos_seconds: float = 10.0          # ... within this many seconds = DDoS (else DoS)

    # ---- response (IPS: what the gateway does after an alert)
    ips_enabled: bool = True            # False = detect only (IDS), True = also block (IPS)
    block_seconds: int = 30             # sure attack from an outside machine: drop all its packets
    quarantine_seconds: int = 120       # sure attack from one of OUR sensors (compromised node): drop longer
    rate_limit_seconds: int = 30        # unsure attack: only slow the sender down
    rate_limit_per_second: int = 20     # packets per second still allowed while rate-limited
