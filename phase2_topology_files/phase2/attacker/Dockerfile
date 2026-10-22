FROM ubuntu:24.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential iproute2 iputils-ping tcpdump libpcap-dev dnsutils && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
CMD ["sleep", "infinity"]
