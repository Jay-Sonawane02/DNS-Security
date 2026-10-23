#!/bin/bash
# Phase 7 — private CA + certificates.
#
# Produces three distinct key/cert pairs, all with OpenSSL, inside a
# disposable container (nothing installed on your actual machine):
#
#   1. A private CA (ca.key/ca.crt) -- installed in the CLIENT's trust
#      store. This is the ONE root of trust for this phase's PKI.
#
#   2. The resolver's own cert (resolver.key/resolver.crt), signed BY
#      that CA, with its DNS Subject Alternative Name set to EXACTLY
#      "resolver.cs6008.local" -- no IP SAN at all, per the spec. The
#      client validates the cert against the hostname it connected to,
#      which only works if the client reaches the resolver BY THAT
#      NAME (see client's extra_hosts in docker-compose.yml), not by
#      raw IP.
#
#   3. A ROGUE cert (rogue.key/rogue.crt) for the SAME name
#      "resolver.cs6008.local", but self-signed -- i.e. NOT chaining
#      to the trusted CA at all. This is what Phase 7.3's attempt (ii)
#      (impersonate the resolver) presents: a cert that matches the
#      hostname perfectly but that no properly-configured client would
#      ever trust, because it doesn't chain to the one CA the client
#      was told to trust. A client bypassing validation (-k or
#      equivalent) is explicitly disallowed by the spec -- this cert
#      is the whole reason that rule matters.
#
# Run this ONCE before `docker compose build` -- and again any time
# you want fresh keys. Re-running is safe (idempotent): always starts
# fresh, never reuses a previous run's keys.
#
# Usage: bash scripts/make-pki.sh

set -euo pipefail
cd "$(dirname "$0")/.."   # phase7/ root, regardless of where invoked from

HOST_UID=$(id -u)
HOST_GID=$(id -g)

docker run --rm \
  -v "$(pwd):/work" \
  -w /work \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  ubuntu:24.04 bash -c '
    set -euo pipefail
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl

    NAME="resolver.cs6008.local"
    mkdir -p /work/resolver/pki /work/client/pki /work/attacker/pki
    cd /tmp

    echo "=== [1/3] Private CA ==="
    openssl ecparam -name prime256v1 -genkey -noout -out ca.key
    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
      -subj "/O=CS6008 Phase7/CN=CS6008 Phase7 Private CA" \
      -out ca.crt
    cp ca.crt /work/client/pki/ca.crt

    echo "=== [2/3] Resolver cert, signed by the CA, SAN=DNS:$NAME only ==="
    openssl ecparam -name prime256v1 -genkey -noout -out resolver.key
    cat > resolver.ext <<EOF2
subjectAltName = DNS:$NAME
extendedKeyUsage = serverAuth
EOF2
    openssl req -new -key resolver.key \
      -subj "/O=CS6008 Phase7/CN=$NAME" \
      -out resolver.csr
    openssl x509 -req -in resolver.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
      -days 825 -sha256 -extfile resolver.ext \
      -out resolver.crt
    cp resolver.key resolver.crt /work/resolver/pki/

    echo "=== [3/3] Rogue cert, SAME name, SELF-signed (not CA-trusted) ==="
    openssl ecparam -name prime256v1 -genkey -noout -out rogue.key
    openssl req -x509 -new -nodes -key rogue.key -sha256 -days 825 \
      -subj "/O=Attacker/CN=$NAME" \
      -addext "subjectAltName = DNS:$NAME" \
      -addext "extendedKeyUsage = serverAuth" \
      -out rogue.crt
    cp rogue.key rogue.crt /work/attacker/pki/

    echo "=== Verifying ==="
    echo "-- resolver.crt chains to our CA (expect OK): --"
    openssl verify -CAfile ca.crt resolver.crt
    echo "-- rogue.crt does NOT chain to our CA (expect verification failure -- this is intentional): --"
    openssl verify -CAfile ca.crt rogue.crt || true

    chown -R "$HOST_UID:$HOST_GID" /work/resolver/pki /work/client/pki /work/attacker/pki
  '

echo ""
echo "Done. PKI ready:"
echo "  client/pki/ca.crt            -- install in client trust store"
echo "  resolver/pki/{resolver.key,resolver.crt} -- for BIND's tls block"
echo "  attacker/pki/{rogue.key,rogue.crt}       -- for the impersonation attack"
echo "Now run: bash scripts/sign-zones.sh && docker compose build && docker compose up -d"
