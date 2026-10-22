#!/bin/bash
set -e
# Only cross-subnet peer root-ns ever needs to reach is the resolver,
# via core-router.
ip route add 172.16.2.0/24 via 172.16.3.3
echo "[root-ns] routes:"; ip route
mkdir -p /var/cache/bind
exec /usr/sbin/named -g -c /etc/bind/named.conf
