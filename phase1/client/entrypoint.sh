#!/bin/bash
set -e
# Only route this host needs: to reach the resolver subnet, go via
# edge-router. It never talks to the authoritative subnet directly --
# that's the whole point of recursive resolution.
ip route add 172.16.2.0/24 via 172.16.1.2

# Point this host's resolver at OUR resolver (172.16.2.10), not Docker's
# embedded DNS, so `dig example.com` / `curl http://example.com` work
# with no extra flags, matching how the spec phrases verification.
echo "nameserver 172.16.2.10" > /etc/resolv.conf

echo "[client] routes:"; ip route
echo "[client] resolv.conf:"; cat /etc/resolv.conf
tail -f /dev/null
