# Phase 6 — Last-Mile Response Forgery

## What's here
Phase 3's signed, validating hierarchy upstream — **completely
untouched**: root-ns/tld-ns/domain-ns still sign their zones, resolver
still validates with `dnssec-validation yes` and its own trust anchor.
What changes:

- **attacker relocates** from the resolver subnet (172.16.2.100,
  Phases 2-5) to the **client subnet** (172.16.1.100). Same binary
  family, same mechanics as Phase 2's forger (in-place A-record RDATA
  overwrite) -- just moved to the one hop DNSSEC never covered: the
  resolver-to-stub link.
- **The diversion route moves from core-router to edge-router**: it's
  now resolver → client replies that get rerouted through the
  attacker (`ip route add 172.16.1.10/32 via 172.16.1.100` on
  edge-router), not auth-server → resolver replies. core-router goes
  back to being a plain router — nothing upstream of the resolver is
  touched in this phase.
- **client gains its own trust-anchor.conf** (the same root KSK the
  resolver trusts, written by `scripts/sign-zones.sh`) so it can run
  `delv` as a **locally-validating client** (Client B) — independent
  of whatever the resolver's reply claims.
- The attacker also unconditionally sets the **`ad` bit** on any
  packet it forges, to make a concrete point for §6.4: nothing on this
  link authenticates that bit either.

## 6.1 Deploy

```bash
cd phase6
bash scripts/sign-zones.sh
docker compose build
docker compose up -d
sudo iptables -I DOCKER-USER -j ACCEPT   # same fix as every phase, re-run after any Docker/system restart
```

**Every time you re-run the signing script, every zone gets brand-new
random keys** — rebuild root-ns, tld-ns, domain-ns, resolver, AND
client together afterward, never just some of them:
```bash
bash scripts/sign-zones.sh
docker compose build root-ns tld-ns domain-ns resolver client
docker compose up -d
```

## 6.2 Verify (forging OFF — must be fully transparent)

```bash
docker exec client dig example.com            # -> 172.16.1.20
docker exec client curl -s http://example.com  # -> the REAL page
```

Also confirm upstream DNSSEC itself is still healthy (unrelated to
the attacker, but worth checking before you blame it for anything):
```bash
docker exec client dig +dnssec example.com     # -> ad flag + RRSIG
docker exec client delv @172.16.2.10 -a /etc/bind/trust-anchor.conf example.com
                                                 # -> ; fully validated
```

## 6.3 Attack

```bash
docker exec attacker touch /tmp/forge.on
docker compose restart resolver && sleep 5   # clears resolver's cache; also
                                              # gives the attacker's MAC
                                              # refresher time to re-ARP
```

### Client A — ordinary stub (trusts whatever the resolver appears to say)

```bash
docker exec client dig example.com             # -> 172.16.1.30, flags include "ad"
docker exec client curl -s http://example.com   # -> the DEFACED page
```
This is the goal: Client A lands on the rogue page. Note the `ad` flag
in the dig output — the attacker set it itself on a record it just
fabricated, and an ordinary stub has no way to tell the difference.

### Client B — locally-validating client (re-derives trust itself)

```bash
docker exec client delv @172.16.2.10 -a /etc/bind/trust-anchor.conf example.com
```
Expect this to **fail validation** (`resolution failed` / no `; fully
validated` line), even though it's querying over the exact same
compromised last-mile path as Client A. `delv` doesn't look at the
`ad` bit at all — it independently fetches the actual RRSIG/DNSKEY
data and re-derives the signature check itself. The attacker can
forge the A record's bytes, but it has no private key for any zone in
the chain, so it cannot produce a matching signature for the record it
just fabricated.

Capture both for evidence (two-terminal tcpdump pattern, same as every
other phase):
```bash
docker exec edge-router tcpdump -i eth0 -w /tmp/phase6_attack.pcap udp port 53
# (separate terminal, once it's listening:)
docker exec client dig example.com
docker exec client delv @172.16.2.10 -a /etc/bind/trust-anchor.conf example.com
# (back in the tcpdump terminal: Ctrl+C)
docker cp edge-router:/tmp/phase6_attack.pcap .
```

### Switching off

```bash
docker exec attacker rm -f /tmp/forge.on
docker compose restart resolver && sleep 5
```

## Checking the chain is actually healthy before you blame the attack

Same trap as every signed phase so far: if 6.2's `dig +dnssec` /
`delv` don't show a healthy chain *before* you touch the attacker, the
chain itself is broken (stale keys from a partial rebuild) — fix that
first.

## Notes for the report (§6.4)

- **Outcome for each client**: Client A (ordinary stub) is fully
  deceived — resolves to `172.16.1.30`, fetches the defaced page, and
  the forged response even carries a (meaningless, self-asserted) `ad`
  flag. Client B (`delv` with its own trust anchor) fails validation
  on the exact same wire path, because it never trusts the `ad` bit in
  the first place.
- **Why upstream DNSSEC doesn't stop this**: validation and trust
  placement are two different things that happen to coincide at the
  resolver in this topology, but don't have to. The resolver *does*
  validate — against the root key it holds as ITS OWN trust anchor.
  But the client never validates anything itself; it just trusts that
  whatever UDP packet shows up claiming to be from 172.16.2.10 is the
  resolver's genuine, already-validated answer. DNSSEC's guarantee
  ends at the last system that actually checks a signature — which is
  the resolver, not the client. Everything downstream of that is
  exactly as vulnerable as Phase 2 ever was, because nothing downstream
  of it was ever covered by the signatures in the first place.
- **The `ad` flag, and why an attacker can set it at will**: `ad` is
  just one bit in the DNS header — entirely unauthenticated, unsigned,
  and mutable by anyone who can touch the packet on the wire, exactly
  like every other header bit. It's meant as a hint from a resolver to
  a client that says "I checked this already" — useful only if the
  channel carrying that hint is itself trusted (e.g. a loopback
  resolver, or an encrypted/authenticated transport — see Phase 7).
  Over a plain, unauthenticated UDP hop, it's just a claim, and this
  interceptor demonstrates that directly by setting it on data it
  fabricated itself. Client B catches the forgery not by reading that
  bit more carefully, but by not trusting it at all: it re-fetches the
  actual DNSSEC records and re-runs the cryptographic check locally,
  which the attacker cannot pass without a private key it doesn't have.

   DELIVERABLES
   phase6/ (relocated attacker, downstream diversion scripts) ·
   logs/captures for both clients · report answers.
