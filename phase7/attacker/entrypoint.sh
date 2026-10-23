#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=0 || true   # we relay in userspace, not via kernel forwarding

echo "[attacker] priming ARP for the client (172.16.1.10)..."
for i in 1 2 3 4 5; do
    ping -c1 -W1 172.16.1.10 >/dev/null 2>&1 || true
    arping -c1 -w1 -I eth0 172.16.1.10 >/dev/null 2>&1 || true
    CLIENT_MAC=$(ip neigh show 172.16.1.10 | awk '{print $5}' | head -n1)
    [ -n "$CLIENT_MAC" ] && break
    sleep 1
done
if [ -z "$CLIENT_MAC" ]; then
    echo "[attacker] FATAL: never got an ARP entry for 172.16.1.10" >&2
    exit 1
fi
echo "[attacker] client MAC = $CLIENT_MAC"
export CLIENT_MAC

# Three independent toggles, same presence-of-file pattern used
# throughout this assignment. Toggle live at any time, no restart
# needed -- see dns_interceptor.cpp's header comment for exactly what
# each one does:
#   docker exec attacker touch /tmp/forge.on    # §2/3/6-style forge (only bites a cleartext fallback)
#   docker exec attacker touch /tmp/tamper.on   # §7.3 (i)
#   docker exec attacker touch /tmp/deny.on     # §7.3 (iii)
# Attempt (ii) (impersonation) doesn't use a flag at all -- see
# tls_endpoint.cpp's header comment and this phase's README for how
# it's tested instead.
for flag in FORGE TAMPER DENY; do
    var="${flag}_ENABLED"
    path="/tmp/$(echo "$flag" | tr '[:upper:]' '[:lower:]').on"
    if [ "${!var:-0}" = "1" ]; then touch "$path"; else rm -f "$path"; fi
done

# tls_endpoint listens on the attacker's own address, 172.16.1.100:853,
# and always presents the rogue cert -- nothing reaches it unless a
# client is deliberately pointed at it (see README, §7.3 attempt (ii)).
/usr/local/bin/tls_endpoint &

exec /usr/local/bin/dns_interceptor eth0
