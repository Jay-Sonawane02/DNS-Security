#!/bin/bash
set -e
ip route add 172.16.2.0/24 via 172.16.3.3
echo "[tld-ns] routes:"; ip route
mkdir -p /var/cache/bind
exec /usr/sbin/named -g -c /etc/bind/named.conf
