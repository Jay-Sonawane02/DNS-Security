#!/bin/bash
# "Client A-permissive" / "Client B-permissive" from §7.3: a client
# that PERMITS cleartext -- it tries DoT first, and if that fails for
# ANY reason (handshake failure, untrusted cert, connection refused or
# timed out), it falls back to an ordinary plain UDP/53 query instead
# of giving up. This is the realistic "compatibility mode" behavior a
# lot of real resolver configs actually ship with, and it's the one
# the report should show getting burned by attempts (i)-(iii): once it
# falls back to cleartext, it's exactly as vulnerable as Phase 2/6 all
# over again, regardless of which TLS-layer trick forced the fallback.
#
# Usage: query-permissive.sh [name]
set -u
NAME="${1:-example.com}"
CA="/etc/ssl/certs/ca-certificates.crt"

echo "[permissive] trying DoT first: kdig +tls @resolver.cs6008.local $NAME"
if OUT=$(kdig +tls +tls-ca="$CA" @resolver.cs6008.local "$NAME" 2>&1); then
    echo "$OUT"
    echo "[permissive] DoT succeeded -- no fallback needed."
else
    echo "$OUT"
    echo "[permissive] DoT failed -- falling back to cleartext UDP/53: dig @172.16.2.10 $NAME"
    dig @172.16.2.10 "$NAME"
fi
