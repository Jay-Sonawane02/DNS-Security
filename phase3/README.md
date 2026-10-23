# Phase 3 — DNSSEC Chain of Trust

## What's here
Identical topology to Phase 2 — same networks, same client/webserver/
rogue-web/routers, same `attacker` (byte-for-byte the Phase 2 binary,
untouched, per the spec). The only things that changed:

- **root-ns, tld-ns, domain-ns** now serve *signed* zones. Each signs
  its own zone; the child's DS record is embedded in the parent zone
  **before** the parent is signed, giving an unbroken chain:
  root KSK → DS(com) → com KSK → DS(example.com) → example.com KSK.
- **resolver** has `dnssec-validation yes;` and a `trust-anchors`
  block installed with the root zone's KSK — the one key trusted
  directly (installed here out of band), with everything else trusted
  transitively through the DS chain.
- **scripts/sign-zones.sh** does the actual signing (ECDSAP256SHA256).

## 3.1 Deploy

```bash
cd phase3
bash scripts/sign-zones.sh   # MUST run before building — produces the
                              # *.zone.signed files named.conf expects,
                              # and resolver/trust-anchor.conf
docker compose build
docker compose up -d
sudo iptables -I DOCKER-USER -j ACCEPT   # same fix as every phase, re-run after any Docker/system restart
```

`sign-zones.sh` runs entirely inside a disposable Ubuntu container
(installs `bind9utils` there, nothing on your actual machine beyond
Docker). It's safe to re-run any time — it always signs fresh from the
plain `.zone` source files, never from a previous signed/modified copy.

**Every time you re-run it, every zone gets brand-new random keys** —
so rebuild all four DNSSEC-related containers together afterward,
never just one:
```bash
bash scripts/sign-zones.sh
docker compose build root-ns tld-ns domain-ns resolver
docker compose up -d
```
Rebuilding only one of these leaves it signed/trusting a different key
than the others, which breaks validation in a way that looks
identical to a real DNSSEC failure — this bit us during development,
worth remembering.

## 3.2 Verify (before touching the attacker)

```bash
docker exec client dig +dnssec example.com
```
Look for the `ad` flag in the header and an `RRSIG` record alongside
the answer — both confirm the resolver validated the full chain for
this answer, not just fetched it.

```bash
docker exec resolver delv @172.16.2.10 -a /etc/bind/trust-anchor.conf example.com
```
The `@172.16.2.10` is important: without it, `delv` tries its own
iterative resolution starting from the *real internet's* root servers
(unreachable from this isolated network) rather than asking our
resolver — which produces a generic `resolution failed: failure`
that has nothing to do with whether your chain is actually healthy.
With the server specified, `delv` independently re-validates the
chain from scratch and prints `; fully validated` on success — a
stronger check than just trusting the `ad` flag on a single `dig`.

## 3.3 Attack — re-run Phase 2's exact attack, unchanged

```bash
docker exec attacker touch /tmp/forge.on
docker compose restart resolver && sleep 3
docker exec client dig example.com
docker exec client curl -s http://example.com
```

Unlike Phase 2, expect this to **fail** — `dig` should show `SERVFAIL`
(or similar) rather than a poisoned answer, and `curl` should get
nothing usable. That failure *is* the correct, expected result: it's
the evidence that DNSSEC validation caught the forged response.

Capture it the same way as Phase 2 (tcpdump on resolver's own
interface, since that's the point that actually sees — and rejects —
the forged packet; see the Phase 1/2 READMEs for the exact two-terminal
capture sequence).

## Checking the chain is actually healthy before you blame the attack

If `3.2`'s plain `dig +dnssec` doesn't show `ad` and a valid RRSIG
*before* you even touch the attacker, don't move on to `3.3` yet — the
chain itself is broken (a missing/wrong DS record, a `named.conf`
still pointing at the wrong file, a stale key from only partially
rebuilding after re-signing, etc.), and the Phase 3 failure you'd see
afterward wouldn't actually be attributable to DNSSEC catching the
attack.

```bash
docker exec root-ns named-checkzone . /etc/bind/zones/root.zone.signed
docker exec tld-ns named-checkzone com /etc/bind/zones/com.zone.signed
docker exec domain-ns named-checkzone example.com /etc/bind/zones/example.com.zone.signed
```
All three should report `OK`.

## Notes for the report (§3.4)

- **What the resolver does with the forged response, and why it
  differs from Phase 2**: the attacker still successfully intercepts
  and rewrites the A record in the final answer — nothing about the
  interception itself changed. What's different is that the forged
  record no longer carries a valid RRSIG matching the real domain-ns
  ZSK (the attacker has no private key for any zone in the chain), so
  resolver's validation fails it specifically at the signature-check
  step, discards it, and returns SERVFAIL instead of caching the
  poisoned address.
- **What's still visible on the wire**: compare this capture against
  your Phase 1 capture — the attacker can still read every query and
  every (forged or genuine) response in full plaintext; DNSSEC adds no
  confidentiality at all. What it adds is origin authentication and
  integrity for the data itself. State this explicitly: DNSSEC
  protects *that the data wasn't tampered with*, not *that anyone
  on-path can't read it*.
- **Algorithm choice**: ECDSAP256SHA256 (algorithm 13) — smaller keys
  and signatures than RSA at comparable security, which matters for
  response size/amplification. Trade-off: marginally more CPU work to
  verify per-signature than RSA, and (outside this lab) somewhat less
  universal legacy-resolver support than RSA/SHA-256 — a non-issue
  here since every resolver in this topology is one you control.
- **Private keys in the repo**: no — `.gitignore` excludes `*.private`
  (and `*.key`, since both regenerate together from
  `scripts/sign-zones.sh` and keeping stale keys around would only
  risk mismatching a freshly re-signed zone). Only the `.signed` zone
  files and `resolver/trust-anchor.conf` — which contains the root
  KSK's **public** DNSKEY only — are committed.
