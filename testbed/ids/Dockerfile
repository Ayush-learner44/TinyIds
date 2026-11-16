# The NEW detector (retrain/pi: one window, one 3-class model). Build context = retrain/ (see docker-compose.yml).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 libpcap0.8 iptables iproute2 \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy lightgbm==4.7.0 scapy==2.6.1 paho-mqtt==2.1.0
COPY pi/run_tinyids.py /app/run_tinyids.py
COPY pi/tinyids /app/tinyids
WORKDIR /app
# admin = the dashboard container (like the laptop on the Pi): its open MQTT connection is not inspected
CMD ["python", "-u", "run_tinyids.py", "interface", "eth0", "port", "1883", "models", "/models", "admin", "172.28.60.40"]
