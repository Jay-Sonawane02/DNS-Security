#!/bin/bash
# "Client A-strict" / "Client B-strict" from §7.3: a client that
# REFUSES cleartext -- it does DoT and nothing else. kdig has no
# built-in cleartext fallback of its own, so a bare `+tls` query
# already behaves exactly this way: if the encrypted transport fails
# for any reason (handshake failure, untrusted cert, connection
# refused/timeout), it just errors out. No wrapper logic needed beyond
# fixing the flags in one place.
#
# The optional second argument overrides WHICH ADDRESS to actually
# connect to, while +tls-hostname always stays "resolver.cs6008.local"
# -- the certificate is still checked against that real hostname
# regardless of where the connection physically goes. This is what
# §7.3 attempt (ii) uses: pointing the connection at the attacker's
# address (172.16.1.100) to test whether its rogue cert for that same
# name gets accepted or rejected, without needing true on-path TCP
# interception to prove the same certificate-validation property.
#
# Usage: query-strict.sh [name] [server_ip]
set -u
NAME="${1:-example.com}"
SERVER="${2:-172.16.2.10}"
CA="/etc/ssl/certs/ca-certificates.crt"   # system trust store, includes our private CA after update-ca-certificates

echo "[strict] kdig +tls @$SERVER +tls-hostname=resolver.cs6008.local $NAME (no fallback if this fails)"
kdig +tls +tls-ca="$CA" +tls-hostname=resolver.cs6008.local @"$SERVER" "$NAME"
exit $?
