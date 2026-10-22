# Phase 1 — Baseline DNS Hierarchy

## What's here
A three-subnet Docker topology (client / resolver / authoritative), with
root-ns → tld-ns → domain-ns delegation, a recursive resolver with
DNSSEC validation explicitly off, and a plain client + webserver. No
attacker yet — this is the baseline every later phase attacks and
defends.

All three Docker networks are `internal: true`: Docker gives them no
gateway and containers get no default route. The *only* way to reach
another subnet is the static route each entrypoint.sh installs,
pointed at the router on that segment — so the isolation check below
(direct query to root-ns fails) is true by construction.

## Build & run
```bash
cd phase1
docker compose build
docker compose up -d
docker compose ps        # all 8 containers should be "running"
```

## Connectivity sanity check (do this before anything DNS-related)
```bash
docker exec client ping -c2 172.16.1.2        # edge-router, same subnet
docker exec resolver ping -c2 172.16.3.10     # root-ns, via core-router
docker exec root-ns ping -c2 172.16.2.10      # resolver, via core-router
```

## Verification (maps to spec §1.2)

**1. Resolution + fetch work end to end:**
```bash
docker exec client dig example.com
docker exec client curl -s http://example.com
```
`dig` should return `172.16.1.20`; `curl` should print the real page's HTML.

**2. Isolation — the authoritative subnet is not directly reachable:**
```bash
docker exec client dig @172.16.3.10 example.com +time=2 +tries=1
```
This should time out / get no answer — `client` has no route to
172.16.3.0/24 at all (only to 172.16.2.0/24, via edge-router).

**3. Capture a full resolution on core-router (it sits on the path to
all three authoritative queries):**
```bash
docker exec core-router tcpdump -i any -w /tmp/phase1.pcap udp port 53 &
docker exec resolver rndc flush        # clear the resolver's cache first
docker exec client dig example.com
# give tcpdump a couple seconds, then stop it
docker exec core-router pkill tcpdump
docker cp core-router:/tmp/phase1.pcap ./phase1.pcap
```
Open `phase1.pcap` in Wireshark (or `tshark -r phase1.pcap`) and pick
out the root, `.com`, and `example.com` exchanges — this is what the
report's referral-chain trace is built from.

**4. Server-side log of every relayed/answered query** (the
assignment's later phases want you contrasting this against
post-encryption opacity — start the habit now):
```bash
docker exec resolver tail -n 50 /var/log/named/queries.log
```

## Troubleshooting
- **`ip route add` fails in an entrypoint** → the container is missing
  `cap_add: [NET_ADMIN]` in docker-compose.yml, or Docker couldn't grant
  it (rootless Docker sometimes needs extra config).
- **`dig` from `client` hangs** → check `docker exec client cat
  /etc/resolv.conf` is `nameserver 172.16.2.10`, and re-check the
  connectivity sanity check above before touching DNS config at all.
- **A nameserver container exits immediately** → `docker compose logs
  root-ns` (or tld-ns/domain-ns/resolver) — almost always a zone-file
  syntax error; `named-checkzone` and `named-checkconf` inside the
  container are your friends:
  ```bash
  docker exec root-ns named-checkzone . /etc/bind/zones/root.zone
  docker exec root-ns named-checkconf /etc/bind/named.conf
  ```

## Teardown
```bash
docker compose down
```
