FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        hping3 nmap python3 python3-paho-mqtt iputils-ping \
    && rm -rf /var/lib/apt/lists/*
COPY attacks/ /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/* \
    && chmod +x /usr/local/bin/*
CMD ["sleep", "infinity"]
