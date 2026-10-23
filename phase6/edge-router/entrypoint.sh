#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1

# This one route is the ENTIRE Phase 6 diversion mechanism -- same
# technique as Phase 2's core-router route, just moved to the other
# side of the resolver and the other router: a more-specific host
# route for the CLIENT's own address, sent via the attacker instead of
# being delivered directly. No ARP spoofing, no change to the client's
# own configuration, no change anywhere upstream of the resolver. No
# "dev ethX" is specified -- the kernel resolves the correct outgoing
# interface from the next-hop's own subnet.
ip route add 172.16.1.10/32 via 172.16.1.100

echo "[edge-router] interfaces:"; ip -4 addr show
echo "[edge-router] routes:"; ip route
tail -f /dev/null
