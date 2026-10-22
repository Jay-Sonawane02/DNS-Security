#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1

# This one route is the ENTIRE Phase 2 diversion mechanism: a
# more-specific host route for the resolver's own address, sent via
# the attacker instead of being delivered directly. No ARP spoofing,
# no other change to this router's normal behavior.
ip route add 172.16.2.10/32 via 172.16.2.100

# Disable checksum/segmentation offload on both interfaces. This is a
# well-documented veth-pair issue (not specific to this setup): the
# kernel can mark a forwarded packet's checksum as "to be completed
# by hardware" (CHECKSUM_PARTIAL), which never actually happens for a
# veth, so it ends up on the wire with an incomplete checksum that
# downstream userspace capture/re-injection can't fix by itself.
ethtool -K eth0 tx off rx off tso off gso off gro off 2>&1 || true
ethtool -K eth1 tx off rx off tso off gso off gro off 2>&1 || true

echo "[core-router] interfaces:"; ip -4 addr show
echo "[core-router] routes:"; ip route
tail -f /dev/null