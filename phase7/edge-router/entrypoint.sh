#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1

# Same single diversion route as Phase 6: a more-specific host route
# for the CLIENT's own address, sent via the attacker instead of
# being delivered directly. This is what §7.3 attempts (i) and (iii)
# use (tamper/deny on resolver -> client traffic). No ARP spoofing,
# nothing else about this router's behavior changes.
ip route add 172.16.1.10/32 via 172.16.1.100

# Attempt (ii) (impersonation) is NOT handled by routing at all --
# the attacker has no interface on resolver_net, so there is no safe
# way to divert client -> resolver traffic to it via routing without
# creating a loop (this router would just re-divert the attacker's
# own relayed packet right back to it). Instead, a DNAT rule rewrites
# the DESTINATION IP of client -> resolver TCP/853 packets to the
# attacker's own address, making the connection terminate there as a
# genuinely new, independent TCP connection -- nothing to relay, so
# nothing to loop. This rule is OFF by default; enable/disable it
# manually as part of §7.3 attempt (ii) (see this phase's README):
#   docker exec edge-router iptables -t nat -A PREROUTING -p tcp -d 172.16.2.10 --dport 853 \
#     -j DNAT --to-destination 172.16.1.100:853
#   docker exec edge-router iptables -t nat -D PREROUTING -p tcp -d 172.16.2.10 --dport 853 \
#     -j DNAT --to-destination 172.16.1.100:853

echo "[edge-router] interfaces:"; ip -4 addr show
echo "[edge-router] routes:"; ip route
tail -f /dev/null
