# The attacker for recording: only the real tools (hping3, nmap). Commands are run with "docker compose exec".
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends hping3 nmap \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
