#!/bin/bash
set -e
sysctl -w net.ipv4.ip_forward=1
echo "[edge-router] forwarding enabled. routes:"; ip route
tail -f /dev/null
