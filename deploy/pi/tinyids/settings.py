"""All TinyIDS settings in one place."""
from dataclasses import dataclass


@dataclass
class Settings:
    interface: str = "wlan0"            # network card to watch
    broker_host: str = "127.0.0.1"      # our Mosquitto runs on the Pi itself
    broker_port: int = 1884             # 1884 = our broker (the lab's broker stays on 1883)
    mqtt_user: str = "tinyids"
    mqtt_password: str = "tinyids123"
    models_folder: str = "models"

    small_window: int = 10              # packets per window for Benign / Recon / Spoofing / Web / BruteForce
    large_window: int = 100             # packets per window for Flood / Mirai (as in CICIoT2023)
    window_timeout: float = 5.0         # close a half-full window after this many seconds
    max_windows_per_second: int = 25    # per sender; extra windows are skipped so the IDS never falls behind

    alert_gap: float = 1.0              # at most one alert per second per sender and attack type
    bruteforce_fails: int = 5           # rule: this many refused MQTT logins ...
    bruteforce_seconds: float = 10.0    # ... within this many seconds = brute force
