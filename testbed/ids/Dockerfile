FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 libpcap0.8 iptables iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir numpy lightgbm==4.7.0 scapy==2.6.1 paho-mqtt==2.1.0
COPY *.py /app/
WORKDIR /app
CMD ["python", "-u", "ids.py"]
