#!/bin/bash
# Phase 3 — DNSSEC signing script.
#
# Signs the zone chain leaf-to-root (example.com -> com -> .), embedding
# each child's DS record into its parent BEFORE signing the parent, and
# extracts the root KSK's DNSKEY record for the resolver's trust anchor.
#
# Run this ONCE before `docker compose build && up` -- and again any
# time you edit a .zone source file. Re-running is safe (idempotent):
# it always starts fresh from the plain .zone source files, never from
# a previously-signed/modified copy, so keys and signatures are
# regenerated cleanly every time rather than accumulating.
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
# Usage: bash scripts/sign-zones.sh   (run from anywhere; finds phase3/ itself)

set -euo pipefail
cd "$(dirname "$0")/.."   # phase3/ root, regardless of where invoked from

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

    echo "=== Extracting root trust anchor for resolver ==="
    # Find the KSK file by its CONTENT (flags=257, algorithm=13), not
    # by threading a variable through -- more robust, and matches the
    # proven-working technique from the reference implementation.
    ROOT_KSK_FILE=$(grep -l "257 3 13" K.+013+*.key | head -n1)
    # Blank out fields 1-6 (name, IN, DNSKEY, flags, protocol, algorithm)
    # and strip ALL whitespace from what remains -- this handles the
    # keys base64 being wrapped across multiple fields in the .key files
    # human-readable formatting, which a fixed-field-number extraction
    # can silently truncate.
    KEY_DATA=$(awk "/DNSKEY 257 3 13/ { \$1=\"\"; \$2=\"\"; \$3=\"\"; \$4=\"\"; \$5=\"\"; \$6=\"\"; print \$0 }" "$ROOT_KSK_FILE" | tr -d " \n\r\t")
    mkdir -p /work/resolver
    printf "trust-anchors {\n    . static-key 257 3 13 \"%s\";\n};\n" "$KEY_DATA" > /work/resolver/trust-anchor.conf
    echo "Trust anchor written:"
    cat /work/resolver/trust-anchor.conf

    chown -R "$HOST_UID:$HOST_GID" /work/domain-ns/zones /work/tld-ns/zones /work/root-ns/zones /work/resolver
  '

echo ""
echo "Done. Signed zones + trust anchor are ready."
echo "Now run: docker compose build root-ns tld-ns domain-ns resolver && docker compose up -d"
