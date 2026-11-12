# TinyIDS detector for the Docker testbed. Uses the SAME code as the Raspberry Pi (deploy/pi).
# Build context = the repository root (see docker-compose.yml).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 libpcap0.8 iptables \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy lightgbm==4.7.0 scapy==2.6.1 paho-mqtt==2.1.0
COPY deploy/pi/run_tinyids.py /app/run_tinyids.py
COPY deploy/pi/tinyids /app/tinyids
WORKDIR /app
CMD ["python", "-u", "run_tinyids.py", "--interface", "eth0", "--port", "1883", "--models", "/models"]
