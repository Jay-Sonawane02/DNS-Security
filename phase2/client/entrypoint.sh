#!/bin/bash
set -e
ip route add 172.16.2.0/24 via 172.16.1.2
echo "nameserver 172.16.2.10" > /etc/resolv.conf
echo "[client] routes:"; ip route
tail -f /dev/null
