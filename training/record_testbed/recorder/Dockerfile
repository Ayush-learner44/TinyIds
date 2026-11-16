# The recorder: the gateway's feature code (retrain/pi) WITHOUT a model. Writes feature rows to /data/*.csv.
# Build context = retrain/ (see docker-compose.yml).
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy scapy==2.6.1
COPY pi/record.py /app/record.py
COPY pi/tinyids /app/tinyids
WORKDIR /app
CMD ["sleep", "infinity"]
