#!/bin/bash
# "Client A-strict" / "Client B-strict" from §7.3: a client that
# REFUSES cleartext -- it does DoT and nothing else. kdig has no
# built-in cleartext fallback of its own, so a bare `+tls` query
# already behaves exactly this way: if the encrypted transport fails
# for any reason (handshake failure, untrusted cert, connection
# refused/timeout), it just errors out. No wrapper logic needed beyond
# fixing the flags in one place.
#
# Usage: query-strict.sh [name]
set -u
NAME="${1:-example.com}"
CA="/etc/ssl/certs/ca-certificates.crt"   # system trust store, includes our private CA after update-ca-certificates

echo "[strict] kdig +tls @resolver.cs6008.local $NAME (no fallback if this fails)"
kdig +tls +tls-ca="$CA" @resolver.cs6008.local "$NAME"
exit $?
