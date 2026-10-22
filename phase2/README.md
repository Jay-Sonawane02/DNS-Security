# Phase 2 — On-Path Response Forgery

## What's here
Everything from Phase 1 unchanged (client, webserver, edge-router,
resolver, root-ns, tld-ns, domain-ns), plus exactly what the spec's
§2.1 asks for:
- **rogue-web** (172.16.1.30) — the defacement page.
- **attacker** (172.16.2.100) — the libpcap interceptor (`dns_interceptor.cpp`).
- **core-router** — one extra route vs Phase 1: `172.16.2.10/32 via
  172.16.2.100` — the entire diversion mechanism. No ARP spoofing.

## How the interceptor works
`attacker` has `ip_forward` off, so nothing reaches the resolver unless
this program explicitly relays it. It sees only UDP/53 traffic addressed
to the resolver (responses, by construction of the diversion route):
- The final `A example.com` answer, when forging is enabled, has its
  4 RDATA bytes overwritten to rogue-web's address.
- Every other packet (referrals, `www.example.com`, anything else) is
  relayed with its DNS content completely untouched.
- **Both the IP header checksum and the UDP checksum are recomputed
  from scratch on every relayed packet, forged or not.** A packet that
  transited a veth pair via core-router's real kernel IP forwarding can
  carry an incomplete "offload placeholder" checksum at either layer —
  looks fine in a raw capture, but gets silently dropped by the
  receiving kernel before it ever reaches the application socket. This
  was the actual cause of persistent SERVFAIL/timeout failures during
  development; recomputing both checksums unconditionally fixed it.
- Uses `pcap_inject` (not `pcap_sendpacket`) — both are spec-compliant,
  this one is simply the one confirmed working in this environment.

Forging starts **off**. Toggle live, no restart needed:
```bash
docker exec attacker touch /tmp/forge.on     # enable
docker exec attacker rm -f /tmp/forge.on     # disable
```

## Build & run
```bash
cd phase2
docker compose build
docker compose up -d
sudo iptables -I DOCKER-USER -j ACCEPT   # Docker's default inter-network forwarding block; re-run after every Docker restart
```

## 2.2 Verify (forging OFF — must be fully transparent)
```bash
docker exec client dig example.com            # -> 172.16.1.20
docker exec client curl -s http://example.com # -> the REAL page
```

## 2.3 Attack (forging ON)
```bash
docker exec attacker touch /tmp/forge.on
docker compose restart resolver                  # clear the cache
docker exec client dig example.com               # -> 172.16.1.30
docker exec client curl -s http://example.com     # -> the DEFACED page
docker exec client dig www.example.com            # -> STILL 172.16.1.20, untouched
```

## Capturing evidence for 2.4
```bash
docker exec -d core-router tcpdump -i any -w /tmp/phase2_attack.pcap udp port 53
docker exec attacker touch /tmp/forge.on
docker compose restart resolver
docker exec client dig example.com
docker exec core-router pkill tcpdump
docker cp core-router:/tmp/phase2_attack.pcap .
```
Open in Wireshark: compare against a capture taken with forging off to
show the contrast (genuine `.20` answer vs forged `.30` answer), and
capture a `www.example.com` lookup during the same attack window as
your "unaffected non-target lookup" evidence.

## Troubleshooting
- **`core-router` container exits immediately** — check `docker compose
  logs core-router`; the diversion route's `ip route add` deliberately
  doesn't hardcode an interface name (`dev ethX`), since Docker doesn't
  guarantee which physical interface gets which name inside a
  multi-network container — letting the kernel resolve it from the
  next-hop's subnet avoids that entirely.
- **Resolver/root-ns/tld-ns/domain-ns crash with `permission denied`
  on `rndc.key`** — this is Ubuntu's default AppArmor profile for
  `named`; `security_opt: ["apparmor:unconfined"]` in docker-compose.yml
  handles it, already applied to all four.
- **Cross-subnet traffic silently times out with no errors anywhere**
  — Docker's own `DOCKER-USER` iptables chain drops forwarded traffic
  between different bridge networks by default, even from a legitimate
  multi-homed router container. Re-run
  `sudo iptables -I DOCKER-USER -j ACCEPT` after every Docker/system
  restart.
- **Attacker relays packets but resolver never gets a usable answer**
  (SERVFAIL, timeouts, despite `pcap_sendpacket`/`pcap_inject`
  reporting success) — this is the checksum-offload issue described
  above. If it recurs, check `docker exec resolver cat /proc/net/snmp
  | grep '^Udp:'` before/after a query — the 8th column
  (`InCsumErrors`) incrementing confirms it.

## Notes for the report (§2.4)
- **Why the attack succeeds**: plain DNS has no field authenticating
  *who* sent a response — only that it matches the outstanding query
  (transaction ID, source port, question). Being genuinely on-path
  (not off-path guessing), the attacker reads the real query and its
  transaction ID straight off the wire and never has to race or guess
  anything an off-path attacker would.
- **Why non-target names are untouched**: the interceptor's forge
  condition is the exact question name (`example.com`, case-folded)
  plus QTYPE A plus an A-type answer present. `www.example.com` fails
  the name check and takes the identical passthrough path as every
  other non-matching packet — there's no special-casing that could
  leak into it.
