#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1

# Same single diversion route as Phase 6: a more-specific host route
# for the CLIENT's own address, sent via the attacker instead of
# being delivered directly. This is what §7.3 attempts (i) and (iii)
# use (tamper/deny on resolver -> client traffic). No ARP spoofing,
# nothing else about this router's behavior changes.
#
# §7.3 attempt (ii) (impersonation) doesn't involve this router at
# all -- see tls_endpoint.cpp's header comment and this phase's
# README for how that one's actually tested.
ip route add 172.16.1.10/32 via 172.16.1.100

echo "[edge-router] interfaces:"; ip -4 addr show
echo "[edge-router] routes:"; ip route
tail -f /dev/null
