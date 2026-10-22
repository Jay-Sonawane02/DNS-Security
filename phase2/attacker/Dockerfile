FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libpcap-dev iproute2 iputils-ping iputils-arping tcpdump dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY dns_interceptor.cpp /app/dns_interceptor.cpp
RUN g++ -O2 -std=c++17 -Wall -o /usr/local/bin/dns_interceptor /app/dns_interceptor.cpp -lpcap

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
