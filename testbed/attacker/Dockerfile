# The attacker = the laptop. Same launch.py and bot.py as retrain/laptop (runs as root, so "sudo" just works).
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        hping3 nmap mosquitto-clients python3 sudo iproute2 \
    && rm -rf /var/lib/apt/lists/*
COPY laptop/launch.py laptop/bot.py /app/
WORKDIR /app
CMD ["sleep", "infinity"]
