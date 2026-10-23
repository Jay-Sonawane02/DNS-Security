#!/bin/bash
# Phase 5 — DNSSEC signing script, parameterized for NSEC (walkable)
# vs NSEC3 (the fix).
#
#   Default (NSEC):   bash scripts/sign-zones.sh
#     -> example.com's denial-of-existence uses plain NSEC, whose
#        "next domain name" field is a readable pointer to the next
#        real owner in the zone -- this is exactly what makes the
#        zone walkable (see zone_walker.cpp's header comment for why).
#
#   --nsec3:           bash scripts/sign-zones.sh --nsec3
#     -> example.com is signed with NSEC3 instead (no extra salt, zero
#        extra hash iterations -- deliberately the cheapest possible
#        NSEC3 configuration, which is itself worth a sentence in the
#        report: it's the minimum change that defeats the walk, not
#        the maximum defense available). A nonexistent name still gets
#        an authenticated denial; the walk just can't read names out
#        of it anymore.
#
# Run this ONCE before `docker compose build && up` -- and again any
# time you edit a .zone source file or switch between NSEC and NSEC3.
# Re-running is safe (idempotent): it always starts fresh from the
# plain .zone source files, never from a previously-signed copy.
#
# IMPORTANT: every time this script runs, every zone gets brand-new
# random keys, so root-ns, tld-ns, domain-ns, AND resolver must all be
# rebuilt together afterward (`docker compose build root-ns tld-ns
# domain-ns resolver`) -- rebuilding only one leaves it out of sync
# with the others' keys, which breaks validation in a way that looks
# identical to an actual DNSSEC failure.
#
# Runs entirely inside a disposable Docker container (installs
# bind9utils there), so nothing needs installing on your actual
# machine beyond Docker itself.
#
# Usage: bash scripts/sign-zones.sh [--nsec3]

set -euo pipefail
cd "$(dirname "$0")/.."   # phase5/ root, regardless of where invoked from

USE_NSEC3=0
if [ "${1:-}" = "--nsec3" ]; then
  USE_NSEC3=1
fi

HOST_UID=$(id -u)
HOST_GID=$(id -g)

docker run --rm \
  -v "$(pwd):/work" \
  -w /work \
  -e HOST_UID="$HOST_UID" \
  -e HOST_GID="$HOST_GID" \
  -e USE_NSEC3="$USE_NSEC3" \
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
    if [ "$USE_NSEC3" = "1" ]; then
      echo "--nsec3: signing example.com with NSEC3 (no salt, 0 extra iterations)."
      dnssec-signzone -3 - -H 0 -K . -o example.com -e +30d -f example.com.zone.signed example.com.zone.signing
    else
      echo "Signing example.com with plain (walkable) NSEC."
      dnssec-signzone -K . -o example.com -e +30d -f example.com.zone.signed example.com.zone.signing
    fi
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

    echo "=== Extracting root trust anchor for resolver ==="
    ROOT_KSK_FILE=$(grep -l "257 3 13" K.+013+*.key | head -n1)
    KEY_DATA=$(awk "/DNSKEY 257 3 13/ { \$1=\"\"; \$2=\"\"; \$3=\"\"; \$4=\"\"; \$5=\"\"; \$6=\"\"; print \$0 }" "$ROOT_KSK_FILE" | tr -d " \n\r\t")
    mkdir -p /work/resolver
    printf "trust-anchors {\n    . static-key 257 3 13 \"%s\";\n};\n" "$KEY_DATA" > /work/resolver/trust-anchor.conf
    echo "Trust anchor written:"
    cat /work/resolver/trust-anchor.conf

    chown -R "$HOST_UID:$HOST_GID" /work/domain-ns/zones /work/tld-ns/zones /work/root-ns/zones /work/resolver
  '

echo ""
if [ "$USE_NSEC3" = "1" ]; then
  echo "Done (NSEC3: walk should fail). Signed zones + trust anchor are ready."
else
  echo "Done (NSEC: walk should succeed). Signed zones + trust anchor are ready."
fi
echo "Now run: docker compose build root-ns tld-ns domain-ns resolver && docker compose up -d"
