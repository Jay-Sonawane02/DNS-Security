# Phase 5 — Zone Walking

## What's here
Phase 3's signed, validating deployment, with two changes:

- **domain-ns**'s zone now has 5 "secret" names never advertised
  anywhere else: `backup`, `staging`, `monitor`, `admin-panel`,
  `internal-vpn`. Their existence is only discoverable by walking the
  denial-of-existence chain.
- **attacker** no longer runs an on-path interceptor. Per the spec's
  own diagram, Phase 5's attacker directly probes domain-ns — there's
  nothing to intercept, the vulnerability lives in what an ordinary,
  individually-addressed query is allowed to return. `core-router` is
  back to being a plain router (no diversion route); attacker just has
  a normal route to the authoritative subnet and queries domain-ns
  like any client would.
- **scripts/sign-zones.sh** signs `example.com` with plain **NSEC** by
  default (walkable) or **NSEC3** with `--nsec3` (the fix).

## 5.1 Deploy

```bash
cd phase5
bash scripts/sign-zones.sh      # NSEC by default — see "Switching modes" below
docker compose build
docker compose up -d
sudo iptables -I DOCKER-USER -j ACCEPT   # same fix as every phase, re-run after any Docker/system restart
```

**Every time you re-run the signing script, every zone gets brand-new
random keys** — rebuild all four DNSSEC-related containers together
afterward, never just one:
```bash
bash scripts/sign-zones.sh [--nsec3]
docker compose build root-ns tld-ns domain-ns resolver
docker compose up -d
```

## 5.2 Verify

```bash
docker exec client dig +dnssec nonexistent-name.example.com
```
Expect `NXDOMAIN`, the `ad` flag, and — in NSEC mode — an `NSEC`
record in the AUTHORITY section whose two name fields bracket where
the query would have sat alphabetically: `<owner> ... NSEC <next>`.
That `<next>` field is the entire vulnerability: it's a *real, existing*
owner name, handed to anyone who asks about a nonexistent one.

## 5.3 Attack

### Run the walk against the NSEC (walkable) deployment

```bash
docker exec -d core-router tcpdump -i any -w /tmp/phase5_nsec_walk.pcap udp port 53
sleep 1
docker exec attacker zone_walker eth0
sleep 1
docker exec core-router pkill tcpdump
docker cp core-router:/tmp/phase5_nsec_walk.pcap .
```
Expect the walker to print all 5 secret names plus `domain-ns` and
`www` (7 names total, excluding the apex itself, which it already
starts from) in well under the `names+2` query budget.

### Switch to NSEC3 and show the walk fails

```bash
bash scripts/sign-zones.sh --nsec3
docker compose build root-ns tld-ns domain-ns resolver
docker compose up -d
```
Re-verify first — §5.2's `dig +dnssec` against a nonexistent name
should still show `ad` and a denial, just with an `NSEC3` record
instead of `NSEC` this time (confirming authenticated denial still
works; only its walkability changed):
```bash
docker exec client dig +dnssec nonexistent-name.example.com
```
Then re-run the exact same walker:
```bash
docker exec attacker zone_walker eth0
```
Expect it to report `Received NSEC3` on the very first query and stop
— zero names recovered, because the "next owner" field is now a hash,
not a name.

### Switching back

```bash
bash scripts/sign-zones.sh
docker compose build root-ns tld-ns domain-ns resolver
docker compose up -d
```

## Checking the chain is actually healthy before you blame the attack

Same trap as every signed phase so far: if §5.2's `dig +dnssec` isn't
showing `ad` and a valid denial record *before* you run the walker,
the chain itself is broken (stale keys from a partial rebuild, a
`named.conf` pointing at the wrong file) — fix that first, since a
walk failing for the wrong reason proves nothing.

## Notes for the report (§5.4)

- **The names recovered and the exact steps**: the walker's own output
  is your evidence here — it prints each query (`[n] Query NSEC for
  <name>`), the next-name it learned from each response, and a final
  summary with the query count against the `names+2` limit. Include
  that output directly.
- **Which configuration made the walk possible, and why signed denial
  leaks what plain DNS doesn't**: plain DNS just returns `NXDOMAIN` for
  a name that isn't there — a direct, computed-on-the-spot answer that
  says nothing about any other name. A *signed* denial can't work that
  way: the signature has to be produced in advance, long before anyone
  knows which nonexistent name will eventually be asked about, so it
  can't be a statement about that specific (unknown, future) query.
  What it signs instead is a statement about the zone's actual
  contents — "nothing exists between this real name and that real
  name" — prepared once at signing time and reused for every query
  that happens to fall in the gap. That statement is only useful if it
  names real, existing owners, which is exactly the information plain
  DNS never needed to disclose.
- **What the NSEC3 fix costs the operator, and what still leaks**:
  NSEC3 trades the readable next-name for a hash of it, at the cost of
  extra computation (hashing) on every signing operation and, if any
  iteration count/salt is added, extra validation cost too — this
  deployment deliberately used the cheapest possible NSEC3 (no salt,
  zero extra iterations) to make the point that walkability, not
  denial-of-existence itself, is the only thing being defended here.
  What an enumerator can still learn afterward: the zone's *size* (the
  count of NSEC3 records is still visible, even with the names
  hashed), and, offline, any name short or guessable enough to be
  found by dictionary/brute-force hashing against the exposed hash
  values — salting and a higher iteration count raise that cost but
  don't eliminate it.

   DELIVERABLES
   phase5/ (the walkable zone and the fixed zone) · enumeration
   steps/commands and the recovered name list · evidence the walk
   fails after the fix · report answers.
