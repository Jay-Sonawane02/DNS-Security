FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 iputils-ping dnsutils knot-dnsutils curl tcpdump ca-certificates openssl \
    && rm -rf /var/lib/apt/lists/*

# Install the private CA into the system trust store -- NOT a -k/
# insecure-bypass workaround; this is the proper, spec-required way
# ("no insecure bypass") for the client to actually trust the
# resolver's real certificate.
COPY pki/ca.crt /usr/local/share/ca-certificates/cs6008-phase7-ca.crt
RUN update-ca-certificates

COPY trust-anchor.conf /etc/bind/trust-anchor.conf
COPY query-strict.sh /usr/local/bin/query-strict.sh
COPY query-permissive.sh /usr/local/bin/query-permissive.sh
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh /usr/local/bin/query-strict.sh /usr/local/bin/query-permissive.sh
ENTRYPOINT ["/entrypoint.sh"]
