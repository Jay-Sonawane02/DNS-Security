#!/bin/bash
set -e
ip route add 172.16.3.0/24 via 172.16.2.3
ip route add 172.16.1.0/24 via 172.16.2.2
ethtool -K eth0 tx off rx off tso off gso off gro off 2>&1 || true  
echo "[resolver] routes:"; ip route
mkdir -p /var/cache/bind
exec /usr/sbin/named -g -c /etc/bind/named.conf