# Phase 2 topology additions

This folder contains the new files for the Phase 2 topology. Start by
copying the full `phase1/` directory to `phase2/`, then add these files
and merge `docker-compose.phase2-services.yml` into `phase2/docker-compose.yml`.

Do not replace the Phase 1 `docker-compose.yml` with the services fragment:
it only contains the two new service definitions.

## Build and verify

From the repository root, after copying `phase1/` to `phase2/` and merging
the two services:

```bash
cd phase2
docker compose config
docker compose build
docker compose up -d
docker compose ps
```

Verify the rogue server is reachable by IP:

```bash
docker exec client curl -s http://172.16.1.30
```

Verify Phase 1 DNS and HTTP still work before proceeding:

```bash
docker exec client dig example.com +short
docker exec client dig www.example.com +short
docker exec client curl -s http://example.com
```

Expected baseline:
- `example.com` -> `172.16.1.20`
- `www.example.com` -> `172.16.1.20`
- `curl http://example.com` displays the real web page.

The attacker container is only a build environment at this stage; it does
not intercept or forge DNS responses yet. Do not add reply-diversion rules
until baseline connectivity has been confirmed.
