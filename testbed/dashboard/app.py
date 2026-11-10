"""TinyIDS dashboard: live sensors, traffic, alerts and the top-3 SHAP reasons of each alert."""
import json
import os
import threading
import time
from collections import deque

import pandas as pd
import paho.mqtt.client as mqtt
import streamlit as st

st.set_page_config(page_title="TinyIDS", layout="wide")

ATTACK_COLORS = {
    "Benign": "#10B981",       # Emerald Green
    "Flood": "#EF4444",        # Crimson Red
    "BruteForce": "#F59E0B",   # Amber / Orange
    "Recon": "#06B6D4",        # Cyan / Sky Blue
    "Spoofing": "#8B5CF6",     # Purple / Violet
    "Mirai": "#EC4899",        # Magenta / Pink
    "Web": "#3B82F6",          # Blue
}


def style_attack(val):
    color = ATTACK_COLORS.get(val, "#94A3B8")
    return f"background-color: {color}25; color: {color}; font-weight: 700; border-left: 3px solid {color}; padding-left: 6px;"


@st.cache_resource
def store():
    s = {"sensors": {}, "alerts": deque(maxlen=300), "stats": deque(maxlen=180), "status": {},
         "connected": False, "lock": threading.Lock()}
    c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="dashboard")
    c.username_pw_set(os.environ["MQTT_USER"], os.environ["MQTT_PASS"])

    def on_connect(cl, _u, _f, rc, _p):
        s["connected"] = rc == 0
        cl.subscribe([("sensors/#", 0), ("ids/#", 0)])

    def on_disconnect(*_a):
        s["connected"] = False

    def on_message(_cl, _u, m):
        try:
            d = json.loads(m.payload)
        except ValueError:
            return
        with s["lock"]:
            if m.topic.startswith("sensors/"):
                s["sensors"][d.get("node", m.topic)] = {**d, "seen": time.time()}
            elif m.topic == "ids/alerts":
                s["alerts"].appendleft(d)
            elif m.topic == "ids/stats":
                s["stats"].append(d)
            elif m.topic == "ids/status":
                s["status"] = d

    c.on_connect, c.on_disconnect, c.on_message = on_connect, on_disconnect, on_message
    c.connect_async(os.environ.get("BROKER", "broker"), 1883, keepalive=30)
    c.loop_start()
    return s


st.title("TinyIDS: live intrusion detection")
st.caption("Sensors publish over MQTT to the gateway; TinyIDS classifies every window of 10 / 100 packets and explains each alert "
           "with its top-3 SHAP features.")


@st.fragment(run_every=1)
def live():
    s = store()
    with s["lock"]:
        sensors = dict(s["sensors"])
        alerts = list(s["alerts"])
        stats = list(s["stats"])
        status = dict(s["status"])
    last = stats[-1] if stats else {}
    recent = [a for a in alerts if a.get("time", "") >= time.strftime("%H:%M:%S", time.localtime(time.time() - 60))]

    m = st.columns(5)
    m[0].metric("Broker", "connected" if s["connected"] else "offline")
    m[1].metric("Packets / s at gateway", last.get("pps", 0))
    m[2].metric("Alerts (last 60 s)", len(recent))
    m[3].metric("Model time / window", f"{last.get('model_ms') or 0:.2f} ms")
    m[4].metric("SHAP time / alert", f"{last.get('shap_ms') or 0:.2f} ms")

    left, right = st.columns([3, 2])
    with left:
        st.subheader("Traffic at the gateway (packets/s)")
        if stats:
            df = pd.DataFrame([{"time": x["time"], "packets/s": x["pps"]} for x in stats]).set_index("time")
            st.line_chart(df, height=230)
        else:
            st.info("waiting for TinyIDS statistics ...")
    with right:
        st.subheader("Sensors")
        if sensors:
            rows = [{"node": k, "temp (C)": v.get("temp_c"), "humidity (%)": v.get("humidity"),
                     "last seen (s ago)": round(time.time() - v["seen"], 1)} for k, v in sorted(sensors.items())]
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
        else:
            st.info("no sensor data yet")

    # Header with Clear Alerts button
    col_a_title, col_a_btn = st.columns([5, 1])
    with col_a_title:
        st.subheader("Alerts")
    with col_a_btn:
        if st.button("🗑️ Clear Alerts", key="clear_alerts_btn", help="Wipe all logged alerts to view fresh traffic"):
            with s["lock"]:
                s["alerts"].clear()
            st.rerun()

    if not alerts:
        st.success("No attacks detected. System is running cleanly.")
    else:
        table = pd.DataFrame([{"time": a["time"], "source IP": a["src"], "attack": a["attack"],
                               "confidence": a["confidence"], "window": a["window"], "detected by": a.get("source", ""),
                               "top-3 reasons": ", ".join(t[0] for t in a["top3"]),
                               "model ms": a["model_ms"], "SHAP ms": a["shap_ms"]} for a in alerts[:50]])
        try:
            style_fn = getattr(table.style, "map", getattr(table.style, "applymap", None))
            styled_table = style_fn(style_attack, subset=["attack"])
            st.dataframe(styled_table, hide_index=True, use_container_width=True, height=270)
        except Exception:
            st.dataframe(table, hide_index=True, use_container_width=True, height=270)

        st.subheader("Why? Top-3 SHAP features of the latest alert of each type")
        latest = {}
        for a in alerts:
            latest.setdefault(a["attack"], a)

        items = list(latest.items())
        # Arrange in a clean 2-column grid instead of 4 crammed columns
        for row_idx in range(0, len(items), 2):
            row_items = items[row_idx:row_idx + 2]
            cols = st.columns(2)
            for col_idx, (name, a) in enumerate(row_items):
                with cols[col_idx]:
                    color = ATTACK_COLORS.get(name, "#38BDF8")
                    st.markdown(
                        f"<div style='border-left: 4px solid {color}; padding-left: 12px; margin-bottom: 8px;'>"
                        f"<span style='font-size: 1.18rem; font-weight: 700; color: {color};'>{name}</span> "
                        f"<span style='font-size: 0.95rem; color: #94A3B8;'>from</span> <code>{a['src']}</code> "
                        f"<span style='font-size: 0.95rem; color: #94A3B8;'>at {a['time']}</span> "
                        f"<span style='font-size: 0.88rem; background: #334155; color: #F8FAFC; padding: 2px 7px; border-radius: 4px; margin-left: 6px;'>conf {a['confidence']:.2f}</span>"
                        f"</div>",
                        unsafe_allow_html=True
                    )
                    if a.get("source") == "rule":
                        for f, v, _ in a["top3"]:
                            st.markdown(f"- **{f}**: `{v}`")
                    else:
                        shap_df = pd.DataFrame({
                            "feature": [f"{t[0]} = {t[1]}" for t in a["top3"]],
                            "SHAP": [t[2] for t in a["top3"]]
                        }).set_index("feature")
                        st.bar_chart(shap_df, horizontal=True, height=200)

            # Thin separator line between rows
            if row_idx + 2 < len(items):
                st.markdown("<hr style='margin: 18px 0; border: none; border-top: 1px solid #334155;' />", unsafe_allow_html=True)

    if status:
        st.caption(f"Model: binary {status['binary']['classes']} (test macro-F1 {status['binary']['test_macro_f1']}), "
                   f"family {status['family']['classes']} (test macro-F1 {status['family']['test_macro_f1']}), "
                   f"{status['features']} features. IDS started {status['started']}.")


live()
