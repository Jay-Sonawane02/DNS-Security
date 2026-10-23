# Phase 7 — Encrypting the Last Mile (DoT)

## What's here
Reuses Phase 6's deployment. Adds:

- **DoT** (DNS-over-TLS, port 853) on the resolver, alongside its
  existing plain port 53 (left up deliberately — attempt (iii) needs a
  resolver that still offers a cleartext door to test blocking
  against).
- A **private CA** + a resolver cert whose DNS SAN is **exactly**
  `resolver.cs6008.local` — no IP SAN. The client reaches the resolver
  by that name (`extra_hosts` in docker-compose.yml) and trusts the CA
  via its real system trust store (`update-ca-certificates` — no
  `-k`/insecure bypass anywhere).
- **edge-router now diverts both directions** of client↔resolver
  traffic through the attacker (Phase 6 only diverted the reply leg)
  — attempt (ii)'s impersonation needs to see the client's initial
  connection too, not just the answer.
- The attacker gains a **second program**, `tls_endpoint` (OpenSSL +
  plain sockets, not libpcap) — see its own header comment for exactly
  why that one piece of this phase can't be a packet forger the way
  everything else in this assignment is: completing a cryptographically
  valid TLS handshake needs a real TLS stack, not crafted bytes.
- Two client query postures, both just thin wrappers around `kdig`:
  `query-strict.sh` (DoT only, no fallback) and `query-permissive.sh`
  (DoT first, falls back to cleartext `dig` on any failure).

## 7.1 Deploy

```bash
cd phase7
bash scripts/make-pki.sh
bash scripts/sign-zones.sh
docker compose build
docker compose up -d
sudo iptables -I DOCKER-USER -j ACCEPT   # same fix as every phase, re-run after any Docker/system restart
```

**Every time you re-run either script, keys/certs regenerate** —
rebuild root-ns, tld-ns, domain-ns, resolver, client, AND attacker
together afterward (attacker bakes in the rogue cert at build time
too):
```bash
bash scripts/make-pki.sh && bash scripts/sign-zones.sh
docker compose build root-ns tld-ns domain-ns resolver client attacker
docker compose up -d
```

## 7.2 Verify

```bash
docker exec client query-strict.sh example.com
```
Expect a clean answer over DoT, `172.16.1.20`. The cert validated
against `resolver.cs6008.local` using the system trust store — no
bypass flags anywhere in `query-strict.sh`.

Confirm upstream DNSSEC still holds (unrelated to DoT, but still true):
```bash
docker exec client delv @172.16.2.10 -a /etc/bind/trust-anchor.conf example.com
```

Confirm **no cleartext DNS at all** crossed edge-router for that
lookup:
```bash
docker exec edge-router timeout 8 tcpdump -i eth0 -nn port 53 or port 853
# (run query-strict.sh again in a second terminal within that window)
```
You should see TCP/853 traffic only — no UDP/53 packets for this
query at all.

## 7.3 Attack — three attempts × two client postures

Each attempt is toggled independently; `forge.on` is also enabled
throughout so that whenever a permissive client *does* fall back to
cleartext, the fallback actually lands on the forged answer rather
than the real one — that combination (TLS-layer attack forces a
fallback → fallback is exactly as vulnerable as Phase 2/6) is the
whole point of this phase.

```bash
docker exec attacker touch /tmp/forge.on
```

### (i) Alter the answer in transit

```bash
docker exec attacker touch /tmp/tamper.on
docker exec client query-strict.sh example.com       # expect: FAILS (TLS error -- integrity check caught the tamper)
docker exec client query-permissive.sh example.com   # expect: DoT fails the same way, falls back to cleartext, LANDS (172.16.1.30)
docker exec attacker rm -f /tmp/tamper.on
```

### (ii) Impersonate the resolver with a rogue certificate

```bash
docker exec attacker touch /tmp/impersonate.on
docker exec client query-strict.sh example.com       # expect: FAILS (cert doesn't chain to the trusted CA)
docker exec client query-permissive.sh example.com   # expect: cert rejected same as strict, falls back to cleartext, LANDS
docker exec attacker rm -f /tmp/impersonate.on
```
Check `docker logs attacker` afterward — `tls_endpoint` logs every
handshake attempt and whether the client accepted or rejected the
rogue cert.

### (iii) Deny the encrypted transport

```bash
docker exec attacker touch /tmp/deny.on
docker exec client query-strict.sh example.com       # expect: FAILS (connection to port 853 just times out / refused)
docker exec client query-permissive.sh example.com   # expect: times out on DoT, falls back to cleartext, LANDS
docker exec attacker rm -f /tmp/deny.on
```

### Switching off

```bash
docker exec attacker rm -f /tmp/forge.on /tmp/tamper.on /tmp/impersonate.on /tmp/deny.on
```

Capture each attempt the same two-terminal way as every other phase
(`docker exec edge-router timeout N tcpdump -i eth0 -w /tmp/phaseN.pcap port 53 or port 853`,
query in a second terminal, `docker cp` the result) for your evidence.

## Checking the chain is actually healthy before you blame the attack

Same trap as every signed phase: if 7.2's verify doesn't pass cleanly
*before* you touch any toggle, fix that first — a PKI/DNSSEC chain
that's already broken makes every attack result meaningless.

## Notes for the report (§7.4)

- **The six outcomes**: all three attempts fail directly against a
  strict client and succeed against a permissive one — but by the
  *same* mechanism every time. None of the three attempts ever
  actually breaks into an established, validly-authenticated TLS
  session; they all just force that session to not exist (tampering
  trips the integrity check and the connection dies; impersonation
  never gets a trusted handshake in the first place; denial just
  blocks the port outright). The strict client treats that as fatal
  and stops. The permissive client treats it as "try the other door,"
  and that other door was never protected by anything this phase
  added — it's exactly Phase 2/6 again.
- **Why upstream DNSSEC doesn't matter here, and why this is a
  genuinely different boundary than Phase 6's**: Phase 6 showed that
  validation happening at the resolver doesn't protect an unauthenticated
  last mile. Phase 7 adds authentication *and* encryption to that same
  last mile, and the attacks still work on the permissive client
  anyway — not because the new protection failed, but because it was
  never actually engaged for that query at all once the fallback fired.
  A protection a client can be talked out of using isn't protecting
  anything.
- **DoT vs DoH**: this deployment uses DoT. DoT is simpler to reason
  about and deploy (a dedicated port, no HTTP semantics, BIND's native
  `tls`/`listen-on tls` support covers it directly) but is also
  trivially distinguishable and blockable on its own fixed port (853
  — exactly what attempt (iii) exploits). DoH's main advantage is
  exactly the opposite of that weakness: sharing port 443 with ordinary
  HTTPS traffic makes it far harder to selectively block without also
  blocking the web, at the cost of needing an HTTP/2 stack and being
  one layer more complex to deploy and operate than DoT.
- **What an encrypted, authenticated last mile still doesn't protect**:
  the fallback decision itself. It protects the bytes on the wire when
  the encrypted channel is actually used, but it does nothing to stop
  a client from deciding, on its own, to stop using it — the exact
  same failure mode Phase 6 demonstrated at the DNSSEC layer shows up
  again here one layer down, because the client's *willingness to
  degrade* was never something cryptography could cover in the first
  place.

   DELIVERABLES
   phase7/ (PKI scripts/certificates, DoT resolver config, both
   client transport configs) · logs/captures of encrypted resolution
   and of each attempt · report answers.
