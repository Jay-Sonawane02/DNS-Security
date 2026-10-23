#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1
# Plain router, same as Phase 1 -- NO diversion route this time. Phase 5's
# attacker isn't on-path intercepting resolver's traffic at all; it directly
# queries domain-ns itself (see attacker/entrypoint.sh's own route to
# 172.16.3.0/24 via this router), exactly like the spec's diagram shows
# ("1. probe" straight from attacker to domain-ns).
echo "[core-router] interfaces:"; ip -4 addr show
echo "[core-router] routes:"; ip route
tail -f /dev/null
