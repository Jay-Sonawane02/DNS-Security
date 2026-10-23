FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    bind9 bind9utils dnsutils iproute2 iputils-ping tcpdump && rm -rf /var/lib/apt/lists/*
COPY named.conf /etc/bind/named.conf
COPY root.hints /etc/bind/root.hints
COPY trust-anchor.conf /etc/bind/trust-anchor.conf
COPY pki/resolver.crt /etc/bind/pki/resolver.crt
COPY pki/resolver.key /etc/bind/pki/resolver.key
COPY entrypoint.sh /entrypoint.sh
# named runs as root here (entrypoint.sh execs it directly, no user
# switch) -- root always has read access to any file regardless of
# ownership, so this just needs to be readable by SOMEONE; no need to
# chown it to the "bind" system user. (An earlier chown-to-bind
# attempt here caused OpenSSL to report a spurious "Permission denied"
# reading the key at TLS-context init -- root happened to not end up
# with read access to that specific owner:mode combination in
# practice, so keep it simple and root-owned instead.)
RUN chmod +x /entrypoint.sh && chmod 600 /etc/bind/pki/resolver.key
ENTRYPOINT ["/entrypoint.sh"]
