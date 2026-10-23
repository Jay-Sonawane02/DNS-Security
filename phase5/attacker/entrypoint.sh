#!/bin/bash
set -e

# Phase 5's attacker isn't on-path -- it directly queries domain-ns
# like any ordinary client, reached through core-router's normal
# routing. This is the one route that makes that possible.
ip route add 172.16.3.0/24 via 172.16.2.3

echo "[attacker] routes:"; ip route
echo "[attacker] ready. Run the walk on demand with:"
echo "  docker exec attacker zone_walker eth0"

tail -f /dev/null
