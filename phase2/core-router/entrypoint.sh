#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1

# This one route is the ENTIRE Phase 2 diversion mechanism: a
# more-specific host route for the resolver's own address, sent via
# the attacker instead of being delivered directly. No ARP spoofing,
# no other change to this router's normal behavior. No "dev ethX" is
# specified -- the kernel resolves the correct outgoing interface from
# the next-hop's own subnet, so this doesn't depend on which interface
# Docker happens to name eth0 vs eth1.
ip route add 172.16.2.10/32 via 172.16.2.100

echo "[core-router] interfaces:"; ip -4 addr show
echo "[core-router] routes:"; ip route
tail -f /dev/null
