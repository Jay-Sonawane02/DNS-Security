FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping dnsutils curl tcpdump && rm -rf /var/lib/apt/lists/*
COPY trust-anchor.conf /etc/bind/trust-anchor.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
