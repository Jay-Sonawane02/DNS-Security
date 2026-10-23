# Phase 4 — Signature Stripping & Downgrade

## What's here
Identical topology to Phase 3 — same networks, same client/webserver/
rogue-web/routers/root-ns/tld-ns/domain-ns/resolver. The only change:
the attacker gains a **strip mode**, independent of (and usable
alongside) the Phase 2/3 forge mode it already had.

- **Forge mode** (`/tmp/forge.on`, unchanged from Phase 2/3): overwrites
  just the 4 RDATA bytes of the A answer in place. Leaves every RRSIG
  exactly as it was — which is *why* Phase 3's validating resolver
  rejects it.
- **Strip mode** (`/tmp/strip.on`, new): for any response whose
  question is `example.com` (any QTYPE — this covers domain-ns's A
  answer, its DNSKEY answer, and tld-ns's referral carrying
  example.com's DS), removes every RRSIG/DNSKEY/DS record wherever it
  appears in the message, and in the same pass forges the A record's
  RDATA. Unlike forge mode, this physically shortens the packet, so
  the DNS header's RR counts, the UDP length, and the IP total length
  all get recomputed — see the comment block at the top of
  `attacker/dns_interceptor.cpp` for the full design rationale.

Two deployment variants, both signed by the same script:
- **Run A**: `bash scripts/sign-zones.sh` — full chain, example.com's
  DS genuinely published in com. Strip mode has to also strip that DS
  (and its RRSIG) from the referral to have any chance at all.
- **Run B**: `bash scripts/sign-zones.sh --omit-example-ds` —
  example.com is fully signed, but com simply never publishes its DS.
  The real operator mistake the phase is about.

## 4.1 Deploy

```bash
cd phase4
bash scripts/sign-zones.sh      # Run A by default; see "Switching runs" below
docker compose build
docker compose up -d
sudo iptables -I DOCKER-USER -j ACCEPT   # same fix as every phase, re-run after any Docker/system restart
```

## 4.2 Verify (before touching the attacker)

```bash
docker exec client dig +dnssec example.com
```
Should show the `ad` flag and a valid RRSIG, exactly like Phase 3 —
confirms the chain is healthy before you attack it.

## 4.3 Attack

### Run A — strip on a fully-delegated (DS-published) zone

```bash
docker exec attacker touch /tmp/strip.on
docker compose restart resolver && sleep 5
docker exec client dig example.com
docker exec client curl -s http://example.com
```
Expect this to **fail** the same way Phase 3's attack did — `SERVFAIL`,
no usable page. Removing the RRSIG/DNSKEY/DS bytes on the wire doesn't
make the zone *look* unsigned to the resolver: the resolver already
holds a secure delegation (the DS it received earlier, or knows com
should have one), so an incomplete/tamper-shaped response for a zone
it expects to be secure is treated as bogus, not as "this zone isn't
signed." Making a zone *genuinely* look unsigned requires a signed
NSEC/NSEC3 proof of DS non-existence from the parent — something the
attacker cannot forge without com's private key.

Capture it the same way as Phase 2/3:
```bash
docker exec -d resolver tcpdump -i eth0 -w /tmp/phase4_runA.pcap udp port 53
sleep 1
docker exec client dig example.com
sleep 1
docker exec resolver pkill tcpdump
docker cp resolver:/tmp/phase4_runA.pcap .
```

### Run B — strip on a zone with no published DS (the operator mistake)

Switch the deployment to the no-DS variant, then rebuild and re-verify
before attacking:
```bash
docker exec attacker rm -f /tmp/strip.on    # back to transparent relay first
bash scripts/sign-zones.sh --omit-example-ds
docker compose build root-ns tld-ns domain-ns resolver
docker compose up -d
sleep 5
docker exec client dig +dnssec example.com   # now NOERROR, no ad flag --
                                              # resolver treats example.com
                                              # as insecure (unvalidated),
                                              # same as Phase 1
```
Now mount the same attack:
```bash
docker exec attacker touch /tmp/strip.on
docker compose restart resolver && sleep 5
docker exec client dig example.com            # -> 172.16.1.30
docker exec client curl -s http://example.com  # -> the DEFACED page
```
This time it **succeeds** — with no secure delegation into
example.com, the resolver never attempts to validate it at all, so
the forged (and now unsigned-looking) answer is accepted exactly as
in Phase 2.

```bash
docker exec -d resolver tcpdump -i eth0 -w /tmp/phase4_runB.pcap udp port 53
sleep 1
docker exec client dig example.com
sleep 1
docker exec resolver pkill tcpdump
docker cp resolver:/tmp/phase4_runB.pcap .
```

### Switching runs back

```bash
docker exec attacker rm -f /tmp/strip.on
bash scripts/sign-zones.sh      # back to Run A's full chain
docker compose build root-ns tld-ns domain-ns resolver
docker compose up -d
```

## Checking the chain is actually healthy before you blame the attack

Same trap as Phase 3: every `sign-zones.sh` run generates brand-new
keys, so rebuild **all four** of root-ns/tld-ns/domain-ns/resolver
together after every run — never just one — or validation breaks in a
way indistinguishable from a real DNSSEC failure. Re-run 4.2's
`dig +dnssec` after any rebuild before concluding an attack result
means anything.

## Notes for the report (§4.4)

- **Run A — why stripping alone can't make a zone look unsigned**:
  signed-ness isn't a bit you can flip by deleting records; it's
  something the *parent* has already told the resolver to expect (via
  the DS it already saw, directly or cached). To genuinely downgrade a
  zone to "insecure," the parent has to supply a signed proof that no
  DS exists — a real cryptographic artifact the attacker cannot
  produce without com's private key. Deleting bytes without supplying
  that proof leaves a response that's internally inconsistent with
  what the resolver already expects, which validators treat as an
  attack signal (bogus/SERVFAIL), not as "unsigned, skip validation."
- **Run B — the single change, and why it reopens the attack**: never
  publishing example.com's DS in com. This isn't something the
  attacker does on the wire — it's a real, persistent misconfiguration
  of the zone itself. With no DS, com's own (genuine) signing produces
  a real, validly-signed NSEC proving no DS RRset exists at the
  delegation point. The resolver sees that proof, correctly concludes
  example.com is a deliberate "island" outside the chain of trust, and
  never attempts to validate anything under it — at which point the
  plain Phase 2-style forgery works again, because there's no
  validation left to defeat.
- **Where downgrade resistance actually comes from**: not from the
  child zone's own signing, but from the parent's affirmative,
  cryptographically signed assertion of the DS RRset's status
  (present, with this digest, or absent — provably). The child cannot
  assert its own security; only the parent, as the already-trusted
  link in the chain, can.
- **The exact operator mistake that forfeits it**: signing a zone and
  never submitting/publishing its DS record to the parent. The zone is
  cryptographically sound in isolation but outside the chain of trust
  entirely — indistinguishable, from the resolver's point of view, from
  a zone that was never signed at all.

   DELIVERABLES
   phase4/ (strip-mode attacker source, scripts for both runs) ·
   logs/captures of Run A and Run B · report answers.
