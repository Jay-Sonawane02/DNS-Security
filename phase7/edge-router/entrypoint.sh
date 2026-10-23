#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1

# TWO diversion routes this time -- Phase 6 only needed resolver-bound
# REPLIES to the client diverted; Phase 7's attempt (ii) (impersonate
# the resolver with a rogue cert) needs the attacker to see the
# CLIENT's initial connection too, not just the reply, so both
# directions of client<->resolver traffic now pass through it. Same
# "it's just a more-specific host route" technique as every other
# phase -- no ARP spoofing, nothing else about this router's behavior
# changes, and the attacker remains a transparent bump-in-the-wire for
# anything it isn't actively modifying.
ip route add 172.16.1.10/32 via 172.16.1.100   # resolver -> client replies
ip route add 172.16.2.10/32 via 172.16.1.100   # client -> resolver queries

echo "[edge-router] interfaces:"; ip -4 addr show
echo "[edge-router] routes:"; ip route
tail -f /dev/null
