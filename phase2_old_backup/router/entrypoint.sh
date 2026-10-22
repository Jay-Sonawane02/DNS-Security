#!/bin/bash
set -e
# A router is directly connected to both subnets it bridges, so it needs
# no static routes of its own -- just IP forwarding, with no NAT. This
# is the ONLY thing that distinguishes a "router" container from any
# other node here: ip_forward=1 means it will relay packets between its
# two interfaces instead of only accepting traffic addressed to itself.
sysctl -w net.ipv4.ip_forward=1
echo "[$(hostname)] forwarding enabled. interfaces:"
ip -4 addr show | grep -E 'inet |^[0-9]+:'
echo "[$(hostname)] routing table:"
ip route
tail -f /dev/null
