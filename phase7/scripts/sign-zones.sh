#!/bin/bash
# Phase 6 — DNSSEC signing script. Identical chain to Phase 3/4/5's
# default (full, walkable-or-not doesn't matter here -- Phase 6 never
# touches denial-of-existence): root-ns signs ., tld-ns signs com with
# example.com's DS embedded, domain-ns signs example.com.
#
# The one addition versus earlier phases: the root KSK trust anchor is
# written to BOTH resolver/trust-anchor.conf (as always) AND
# client/trust-anchor.conf -- Phase 6's Client B (a locally-validating
# client, e.g. delv) needs its OWN copy of the same public root key to
# independently re-verify the chain itself, rather than trusting
# whatever the resolver's reply claims.
#
# Run this ONCE before `docker compose build && up` -- and again any
# time you edit a .zone source file. Re-running is safe (idempotent):
# it always starts fresh from the plain .zone source files.
#
# IMPORTANT: every time this script runs, every zone gets brand-new
# random keys, so root-ns, tld-ns, domain-ns, resolver, AND client
# must all be rebuilt together afterward -- rebuilding only some of
# them leaves the others out of sync, which breaks validation in a way
# that looks identical to an actual DNSSEC failure.
#
# Runs entirely inside a disposable Docker container (installs
# bind9utils there), so nothing needs installing on your actual
# machine beyond Docker itself.
#
# Usage: bash scripts/sign-zones.sh

set -euo pipefail
cd "$(dirname "$0")/.."   # phase6/ root, regardless of where invoked from

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
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq bind9utils bind9-dnsutils

    ALG=ECDSAP256SHA256

    echo "=== [1/3] Signing example.com (domain-ns) ==="
    cd /work/domain-ns/zones
    rm -f K*.key K*.private *.signed dsset-* example.com.zone.signing 2>/dev/null || true
    cp example.com.zone example.com.zone.signing
    EX_KSK=$(dnssec-keygen -a "$ALG" -f KSK example.com)
    EX_ZSK=$(dnssec-keygen -a "$ALG" example.com)
    cat "${EX_KSK}.key" "${EX_ZSK}.key" >> example.com.zone.signing
    dnssec-signzone -K . -o example.com -e +30d -f example.com.zone.signed example.com.zone.signing
    echo "example.com DS record:"; cat "dsset-example.com."

    echo "=== [2/3] Signing com (tld-ns) ==="
    cd /work/tld-ns/zones
    rm -f K*.key K*.private *.signed dsset-* com.zone.signing 2>/dev/null || true
    cp com.zone com.zone.signing
    cat /work/domain-ns/zones/dsset-example.com. >> com.zone.signing
    COM_KSK=$(dnssec-keygen -a "$ALG" -f KSK com)
    COM_ZSK=$(dnssec-keygen -a "$ALG" com)
    cat "${COM_KSK}.key" "${COM_ZSK}.key" >> com.zone.signing
    dnssec-signzone -K . -o com -e +30d -f com.zone.signed com.zone.signing
    echo "com DS record:"; cat "dsset-com."

    echo "=== [3/3] Signing root (root-ns) ==="
    cd /work/root-ns/zones
    rm -f K*.key K*.private *.signed dsset-* root.zone.signing 2>/dev/null || true
    cp root.zone root.zone.signing
    cat /work/tld-ns/zones/dsset-com. >> root.zone.signing
    ROOT_KSK=$(dnssec-keygen -a "$ALG" -f KSK .)
    ROOT_ZSK=$(dnssec-keygen -a "$ALG" .)
    cat "${ROOT_KSK}.key" "${ROOT_ZSK}.key" >> root.zone.signing
    dnssec-signzone -K . -o . -e +30d -f root.zone.signed root.zone.signing

    echo "=== Extracting root trust anchor for resolver AND client ==="
    ROOT_KSK_FILE=$(grep -l "257 3 13" K.+013+*.key | head -n1)
    KEY_DATA=$(awk "/DNSKEY 257 3 13/ { \$1=\"\"; \$2=\"\"; \$3=\"\"; \$4=\"\"; \$5=\"\"; \$6=\"\"; print \$0 }" "$ROOT_KSK_FILE" | tr -d " \n\r\t")
    mkdir -p /work/resolver /work/client
    printf "trust-anchors {\n    . static-key 257 3 13 \"%s\";\n};\n" "$KEY_DATA" > /work/resolver/trust-anchor.conf
    printf "trust-anchors {\n    . static-key 257 3 13 \"%s\";\n};\n" "$KEY_DATA" > /work/client/trust-anchor.conf
    echo "Trust anchor written (resolver + client):"
    cat /work/resolver/trust-anchor.conf

    chown -R "$HOST_UID:$HOST_GID" /work/domain-ns/zones /work/tld-ns/zones /work/root-ns/zones /work/resolver /work/client
  '

echo ""
echo "Done. Signed zones + trust anchors (resolver + client) are ready."
echo "Now run: docker compose build root-ns tld-ns domain-ns resolver client && docker compose up -d"
