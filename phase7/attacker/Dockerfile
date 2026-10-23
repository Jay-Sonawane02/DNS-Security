FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential libpcap-dev libssl-dev iproute2 iputils-ping iputils-arping \
      tcpdump dnsutils iptables \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY dns_interceptor.cpp /app/dns_interceptor.cpp
COPY tls_endpoint.cpp /app/tls_endpoint.cpp
RUN g++ -O2 -std=c++17 -Wall -o /usr/local/bin/dns_interceptor /app/dns_interceptor.cpp -lpcap -lpthread \
 && g++ -O2 -std=c++17 -Wall -o /usr/local/bin/tls_endpoint /app/tls_endpoint.cpp -lssl -lcrypto -lpthread

COPY pki/rogue.crt /app/pki/rogue.crt
COPY pki/rogue.key /app/pki/rogue.key

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
