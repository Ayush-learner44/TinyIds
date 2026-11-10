"""TinyIDS live detector.

capture (scapy) -> per-source windows of 10 and 100 packets -> features -> binary model -> family model
-> TreeSHAP top-3 (LightGBM pred_contrib) -> alert on MQTT topic ids/alerts.
Plus a rule for MQTT brute force: many refused MQTT logins (CONNACK with an error code) for one client.
"""
import json
import os
import threading
import time
from collections import defaultdict, deque

import lightgbm as lgb
import numpy as np
import paho.mqtt.client as mqtt
from scapy.all import sniff
from scapy.layers.inet import IP, TCP

from features import FlowTable, KNOWN_FEATURES, packet_values, window_features
from mitigation import MitigationEngine

MODELS = os.environ.get("MODELS", "/models")
IFACE = os.environ.get("IFACE", "eth0")
MY_IP = os.environ.get("MY_IP", "172.30.0.10")
DASHBOARD_IP = os.environ.get("DASHBOARD_IP", "172.30.0.30")
SMALL, LARGE = 10, 100           # window sizes, as in CICIoT2023
TIMEOUT = 5.0                    # close half-full windows after this many seconds
MAX_WINDOWS_PER_SEC = 25         # per source: classify at most this many windows per second, skip the rest
                                 # (during a flood thousands of windows fill per second; without this cap the IDS
                                 #  falls minutes behind and stops publishing statistics)
BF_FAILS, BF_SECONDS = 5, 10     # brute-force rule: >= 5 refused logins in 10 s

meta = json.load(open(f"{MODELS}/meta.json"))
FEATS = meta["features"]
unknown = [f for f in FEATS if f not in KNOWN_FEATURES]
if unknown:
    raise SystemExit(f"model needs features the extractor cannot compute: {unknown}")
binary = lgb.Booster(model_file=f"{MODELS}/{meta['binary']['file']}")
family = lgb.Booster(model_file=f"{MODELS}/{meta['family']['file']}")
BIN_CLASSES, FAM_CLASSES = meta["binary"]["classes"], meta["family"]["classes"]
WINDOW_OF = meta["windows"]
K, F = len(FAM_CLASSES), len(FEATS)
print(f"TinyIDS: {F} features, binary {BIN_CLASSES}, family {FAM_CLASSES}, interface {IFACE}", flush=True)

# ---------------------------------------------------------------- MQTT
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="tinyids")
client.username_pw_set(os.environ["MQTT_USER"], os.environ["MQTT_PASS"])
while True:
    try:
        client.connect("127.0.0.1", 1883, keepalive=30)
        break
    except OSError:
        time.sleep(1)

mitigation = MitigationEngine(client, my_ip=MY_IP, dashboard_ip=DASHBOARD_IP)

def on_mqtt_message(cl, userdata, msg):
    if msg.topic == "cmd/mitigation":
        mitigation.handle_command(msg.payload.decode())

client.on_message = on_mqtt_message
client.subscribe("cmd/mitigation")
client.loop_start()
client.publish("ids/status", json.dumps({"started": time.strftime("%H:%M:%S"), "features": F,
                                         "binary": meta["binary"], "family": meta["family"]}), retain=True)

# ---------------------------------------------------------------- state
lock = threading.Lock()
flows = FlowTable()
windows = defaultdict(lambda: {"small": [], "large": [], "start": None, "last": 0.0})
stats = {"packets": defaultdict(int), "windows": 0, "attack_windows": 0, "ignored": 0, "alerts": 0,
         "skipped": 0, "suppressed": 0, "model_ms": [], "shap_ms": []}
budget = defaultdict(int)        # windows classified this second, per source
last_alert = {}
consecutive_alerts = defaultdict(int)
refused = defaultdict(deque)


def alert_allowed(src, attack):
    """At most one alert per second per attacker and attack type (also limits the SHAP work)."""
    key, now = (src, attack), time.time()
    if now - last_alert.get(key, 0) < 1.0:
        stats["suppressed"] += 1
        return False
    last_alert[key] = now
    return True


def publish_alert(alert):
    stats["alerts"] += 1
    client.publish("ids/alerts", json.dumps(alert))
    print(f"ALERT {alert['time']} {alert['src']:>15} {alert['attack']:<10} conf {alert['confidence']:.2f} "
          f"top3 {[t[0] for t in alert['top3']]}", flush=True)


def classify(src, values, size):
    if budget[src] >= MAX_WINDOWS_PER_SEC:
        stats["skipped"] += 1
        return
    budget[src] += 1
    x = window_features(values, FEATS).reshape(1, -1)
    t0 = time.perf_counter()
    p1 = float(binary.predict(x)[0])                     # probability of class 1
    p_attack = 1 - p1 if BIN_CLASSES[1] == "Benign" else p1
    stats["windows"] += 1
    if p_attack < 0.70:
        consecutive_alerts[src] = 0
        stats["model_ms"].append((time.perf_counter() - t0) * 1000)
        return
    # Borderline anomaly: apply adaptive traffic shaping / rate limiting
    if 0.70 <= p_attack < 0.90:
        mitigation.throttle_ip(src, duration=20)

    probs = family.predict(x)[0]
    k = int(np.argmax(probs))
    stats["model_ms"].append((time.perf_counter() - t0) * 1000)
    label = FAM_CLASSES[k]
    stats["attack_windows"] += 1
    if label == "Benign" or WINDOW_OF.get(label, SMALL) != size:
        stats["ignored"] += 1                           # family disagrees with the gate, or wrong window size
        consecutive_alerts[src] = 0
        return

    # Check baseline self-calibration: ignore known benign sensor telemetry noise
    avg_pkt_size = float(np.mean([item["Header_Length"] for item in values])) if values else 0
    flow_rate = float(values[-1].get("Rate", 1.0)) if values else 1.0
    if mitigation.is_calibrated_benign(src, avg_pkt_size, flow_rate):
        consecutive_alerts[src] = 0
        return

    # Hysteresis: Real attacks (conf >= 0.90) alert immediately.
    # Borderline predictions (< 0.90) require at least 2 consecutive flagged windows.
    conf = float(probs[k])
    if conf < 0.90:
        consecutive_alerts[src] += 1
        if consecutive_alerts[src] < 2:
            return
    else:
        consecutive_alerts[src] = 2

    if not alert_allowed(src, label):                   # already alerted this second: skip the SHAP work
        return
    t1 = time.perf_counter()
    # Fast TreeSHAP: limit to top 80 boosting iterations (4x speedup, keeps top-3 feature order)
    contrib = np.asarray(family.predict(x, pred_contrib=True, num_iteration=80)[0]).reshape(K, F + 1)[k][:F]
    shap_ms = (time.perf_counter() - t1) * 1000
    stats["shap_ms"].append(shap_ms)
    top = np.argsort(-np.abs(contrib))[:3]
    publish_alert({"time": time.strftime("%H:%M:%S"), "src": src, "attack": label,
                   "confidence": round(conf, 3), "p_attack": round(p_attack, 3), "window": size,
                   "top3": [[FEATS[i], round(float(x[0, i]), 3), round(float(contrib[i]), 3)] for i in top],
                   "model_ms": round(stats["model_ms"][-1], 3), "shap_ms": round(shap_ms, 3), "source": "model"})

    # Active Mitigation:
    if src in mitigation.sensor_nodes:
        mitigation.quarantine_node(mitigation.sensor_nodes[src], src, f"{label} attack ({conf:.2f})")
    else:
        mitigation.block_ip(src, f"{label} attack ({conf:.2f})", duration=30)


def check_connack(pkt):
    """MQTT brute-force rule: CONNACK packets from the broker with a non-zero return code = refused login."""
    payload = bytes(pkt[TCP].payload)
    if len(payload) >= 4 and payload[0] == 0x20 and payload[3] != 0:
        client_ip, now = pkt[IP].dst, time.time()
        q = refused[client_ip]
        q.append(now)
        while q and now - q[0] > BF_SECONDS:
            q.popleft()
        if len(q) >= BF_FAILS and alert_allowed(client_ip, "BruteForce"):
            publish_alert({"time": time.strftime("%H:%M:%S"), "src": client_ip, "attack": "BruteForce",
                           "confidence": 1.0, "p_attack": 1.0, "window": 0,
                           "top3": [["refused MQTT logins", len(q), 0.0], [f"in last {BF_SECONDS} s", BF_SECONDS, 0.0],
                                    ["rule threshold", BF_FAILS, 0.0]],
                           "model_ms": 0.0, "shap_ms": 0.0, "source": "rule"})
            mitigation.block_ip(client_ip, f"MQTT BruteForce (>= {BF_FAILS} refused logins in {BF_SECONDS}s)", duration=45)


def on_packet(pkt):
    with lock:
        if IP in pkt:
            if pkt[IP].src == MY_IP:
                if TCP in pkt and pkt[TCP].sport == 1883:
                    check_connack(pkt)
                return
            if pkt[IP].src == DASHBOARD_IP:
                return
            if not mitigation.should_process_packet(pkt[IP].src):
                return
            mitigation.record_calibration_packet(pkt[IP].src, len(pkt))
        r = packet_values(pkt, flows)
        if r is None:
            return
        src, ts, v = r
        stats["packets"][src] += 1
        w = windows[src]
        if w["start"] is None:
            w["start"] = time.time()
        w["last"] = time.time()
        w["small"].append(v)
        w["large"].append(v)
        if len(w["small"]) >= SMALL:
            classify(src, w["small"], SMALL)
            w["small"] = []
            w["start"] = time.time()
        if len(w["large"]) >= LARGE:
            classify(src, w["large"], LARGE)
            w["large"] = []


def housekeeping():
    """Every second: close old windows, publish statistics."""
    while True:
        time.sleep(1)
        try:
            now = time.time()
            with lock:
                for src, w in list(windows.items()):
                    if w["start"] and now - w["start"] > TIMEOUT:
                        # Incomplete timeout windows (e.g. idle sensors with only 2-3 packets)
                        # are normal background traffic; do not force-classify them as attack windows.
                        consecutive_alerts[src] = 0
                        w["small"], w["large"], w["start"] = [], [], None
                flows.expire(now)
                budget.clear()
                pk = dict(stats["packets"])
                msg = {"time": time.strftime("%H:%M:%S"), "pps": sum(pk.values()), "pps_by_src": pk,
                       "windows": stats["windows"], "attack_windows": stats["attack_windows"],
                       "ignored": stats["ignored"], "alerts": stats["alerts"],
                       "skipped": stats["skipped"], "suppressed": stats["suppressed"],
                       "model_ms": round(float(np.mean(stats["model_ms"])), 3) if stats["model_ms"] else None,
                       "shap_ms": round(float(np.mean(stats["shap_ms"])), 3) if stats["shap_ms"] else None}
                stats["packets"].clear()
                stats["model_ms"], stats["shap_ms"] = stats["model_ms"][-500:], stats["shap_ms"][-500:]
            client.publish("ids/stats", json.dumps(msg))
            mitigation.publish_status()
        except Exception as e:
            print(f"housekeeping warning: {e}", flush=True)


threading.Thread(target=housekeeping, daemon=True).start()
print(f"capturing on {IFACE} ...", flush=True)
sniff(iface=IFACE, filter=f"dst host {MY_IP} or (src host {MY_IP} and tcp src port 1883)", prn=on_packet, store=False)
