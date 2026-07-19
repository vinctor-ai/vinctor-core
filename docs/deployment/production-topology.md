# Production deployment topology + TLS reference

This is a tested reference for standing up Vinctor with real TLS, a durable
backend, and an independent audit-anchor sink — the topology operators otherwise
have to assemble themselves. It is a self-hosted runtime reference, not a managed
HA control plane (see [What this does not provide](#what-this-does-not-provide)).

Related material:

- [self-hosting.md](self-hosting.md) — configuration surface, container image,
  operator/storage commands.
- [operational-runbooks.md](operational-runbooks.md) — bare-metal systemd, nginx
  and Caddy proxy snippets, firewall, backup/restore.
- [postgres.md](postgres.md) — the Postgres backend contract.
- [preview-runbook.md](preview-runbook.md) — the single-partner preview stack
  under `deploy/preview/` (SQLite + Caddy), including key bootstrap and the
  authz smoke.

## Topologies

### Single-box (SQLite)

One host, SQLite state, a reverse proxy in front for TLS. Appropriate for a
single low-volume deployment where one process owns the database file.

- Quickstart, loopback only, no TLS: the root [`compose.yaml`](../../compose.yaml)
  (`docker compose up`, then `curl http://127.0.0.1:8765/healthz`).
- With TLS for a single partner: `deploy/preview/` (Caddy + SQLite) — see
  [preview-runbook.md](preview-runbook.md).

### Multi-instance (Postgres)

The reference stack in [`deploy/reference/`](../../deploy/reference/):

```
client --HTTPS--> caddy (TLS termination) --HTTP--> vinctor --> postgres
                                                       |
                                                       +--> audit-anchor volume
```

- **caddy** terminates TLS and is the only network entry point (`80`/`443`).
- **vinctor** runs `vinctor service serve` with the Postgres backend and is
  reachable only inside the compose network — it never publishes `8765` to the
  host.
- **postgres** holds the durable control-plane state and the single global
  tamper-evident audit chain that is serialized across service instances.
- the **audit-anchor** chain-head stream is written to a dedicated volume,
  independent of the database.

Horizontal scale is by running the same `vinctor` service on additional hosts
against the **same** Postgres. Separate processes coordinate through Postgres
constraints and advisory locks (see [postgres.md](postgres.md)); put a load
balancer in front that routes only to instances returning `200` from `/readyz`.

## Service surface

Verified against `src/vinctor_service/local_http.py` and `service_config.py`.

### Endpoints

| Path | Method | Auth | Purpose |
| --- | --- | --- | --- |
| `/healthz` | GET | none | Liveness. `200 {"status":"ok","service":"vinctor-service","mode":...}`. Never touches the database; exempt from the rate limiter (GET only). |
| `/readyz` | GET | none | Readiness. `200 {"status":"ready",...}` when the store answers `SELECT 1`; `503 {"status":"unavailable",...}` otherwise (fails closed, leaks no connection detail). |
| `/metrics` | GET | **none** | Prometheus text (`Content-Type: text/plain; version=0.0.4`). Present only when metrics are enabled; otherwise `404`. Because it is unauthenticated, keep it off the public edge. |
| `/v1/enforce`, `/v1/enforce/delegated` | POST | agent key | Authorization decisions. |
| `/v1/observe`, `/v1/simulate` | POST | agent key | Gradual-rollout modes. |
| `/v1/tokens` | POST | agent key | Subject-token mint. |
| `/v1/grants`, `/v1/grant-requests`, `/v1/boundaries`, `/v1/auto-approval-rules`, `/v1/audit-events` | various | workspace / auditor key | Control-plane and audit. |

Only `/healthz`, `/readyz`, and `/metrics` are unauthenticated. Vinctor reads
`X-Workspace-Key`, `X-Agent-Key`, and `X-Vinctor-Boundary-Id` request headers;
the proxy must forward them unchanged.

### Configuration

`vinctor service serve` reads CLI flags first, then environment variables
(`service_config.py`). Fields used by the reference stack:

| Env var | Default | Reference value | Notes |
| --- | --- | --- | --- |
| `VINCTOR_HOST` | `127.0.0.1` | `0.0.0.0` | Bind inside the container network only; never published to the host. |
| `VINCTOR_PORT` | `8765` | `8765` | Internal port; `expose`d, not `ports`-mapped. |
| `VINCTOR_SERVICE_MODE` | `local` | `self_hosted` | `local` or `self_hosted`. |
| `VINCTOR_LOG_LEVEL` | `info` | `info` | `debug`/`info`/`warning`/`error`. |
| `VINCTOR_STORAGE_BACKEND` | `sqlite` | `postgres` | `postgres` requires `VINCTOR_POSTGRES_DSN`. |
| `VINCTOR_POSTGRES_DSN` | — | `postgresql://…@postgres:5432/vinctor` | Never logged; the startup banner prints only `postgres`. |
| `VINCTOR_METRICS` | off | `true` | Enables `/metrics`. |
| `VINCTOR_RATE_LIMIT_PER_MINUTE` | off | `600` | Fixed-window, per-source, fail-open availability guard. |
| `VINCTOR_TRUSTED_PROXIES` | none (trust none) | compose subnet CIDR | Required for correct client attribution behind the proxy — see below. |
| `VINCTOR_AUDIT_ANCHOR` | off | `file:/data/chain-heads.jsonl` | `stdout` or `file:/abs/path`; independent sink. Path must be writable by uid 10001 — see [audit-anchor sink](#independent-audit-anchor-sink). |

OIDC role mapping (`VINCTOR_OIDC_*`) and opt-in audit export
(`VINCTOR_AUDIT_EXPORT` — `stdout`, `file:`, or `otlp-http:`) are documented in
[self-hosting.md](self-hosting.md) and layer on unchanged.

## TLS termination

TLS terminates at Caddy; the backend is plain HTTP over the private network.
`deploy/reference/Caddyfile`:

```caddy
{$VINCTOR_PUBLIC_HOSTNAME:localhost} {
	request_body {
		max_size 64KiB
	}
	@metrics path /metrics
	respond @metrics 404
	reverse_proxy vinctor:8765
}
```

- For a public hostname, Caddy obtains and renews ACME certificates
  automatically. For `localhost` it uses a local CA — clients need `-k` or the
  local root trusted.
- `max_size 64KiB` (65536 bytes) matches the server-side `MAX_BODY_BYTES` cap
  exactly (defense-in-depth). Note `64KiB` = 65536 while Caddy reads `64KB` as
  65000; use the `KiB` form so the edge cap is not smaller than the server's.
- `/metrics` is blocked at the edge because it is unauthenticated; scrape it
  in-network at `http://vinctor:8765/metrics` (from a Prometheus scraper on
  `vinctor-net`, not from the host — that name resolves only inside the network).
- An nginx equivalent (with the correct `X-Forwarded-For` handling) is in
  [operational-runbooks.md](operational-runbooks.md#tls--reverse-proxy).

## Trusted proxy and X-Forwarded-For

The per-source rate limiter must attribute requests to the real client, not to
the proxy. `resolve_rate_limit_source` (`src/vinctor_service/ratelimit.py`):

1. With `VINCTOR_TRUSTED_PROXIES` unset it trusts no proxy and keys on the socket
   peer verbatim — so behind a proxy every request would share the proxy's
   bucket.
2. With the proxy's address listed as trusted, it walks `X-Forwarded-For`
   right-to-left and takes the first entry that is not itself a trusted proxy.

That walk is sound **only** if every trusted proxy appends the socket-proved peer
address to `X-Forwarded-For` (Caddy 2.5+ and most cloud load balancers do; nginx
needs `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`). Otherwise a
client can fabricate the whole header and trusting the proxy *disables* the
limiter instead of sharpening it.

Trust only the network the proxy actually connects from — never `0.0.0.0/0`. The
reference compose pins `vinctor-net` to `172.28.0.0/16` and sets
`VINCTOR_TRUSTED_PROXIES` to that CIDR; change both together. This is the
proxy-aware attribution that per-tenant rate limiting (PKA-22) builds on.

## Secret injection

- Copy `deploy/reference/.env.example` to `.env` and fill it. **Never commit
  `.env`.** It carries non-secret config plus `POSTGRES_PASSWORD`.
- Vinctor workspace/agent/operator keys are **not** set via environment. The
  service does not mint authority on startup; bootstrap keys through the operator
  CLI after first boot (only hashes are stored) and hand raw keys to callers
  out-of-band. See the bootstrap steps in
  [self-hosting.md](self-hosting.md#bootstrap-and-hook-environment) and
  [preview-runbook.md](preview-runbook.md).
- The startup banner and audit export never print the DSN or raw keys.

## Independent audit-anchor sink

Each committed audit chain head `{seq, row_hash, created_at}` is emitted to the
configured anchor sink, fail-open (`src/vinctor_service/audit_anchor.py`). The
reference stack writes to a dedicated `audit-anchor` volume
(`file:/data/chain-heads.jsonl`) that is independent of the database (Postgres),
so the tamper-evidence record survives and can be shipped off-box.

The anchor is mounted at `/data` on purpose: the image creates and chowns that
path to the non-root service user, and it is inert under the Postgres backend
(the sqlite DB path is unused). A fresh named volume mounted onto a pre-chowned
path inherits its ownership, so the service user can append. Mounting at a path
the image never creates (e.g. `/anchor`) yields a root-owned mountpoint, and
because the anchor is fail-open every append would be silently dropped — a green
stack with an empty tamper-evidence stream. `smoke.sh --anchor-file` guards
against exactly that regression.

For real tamper-evidence, forward this stream to an append-only / WORM store or
SIEM off the service host — a local file an operator can rewrite is not an
independent anchor. Run one anchor destination per process; do not point two
processes at one shared file. Opt-in `VINCTOR_AUDIT_EXPORT=otlp-http:<endpoint>`
can additionally stream full events to a collector.

## Health and readiness wiring

- Container `healthcheck` probes `/readyz` (already wired in both compose files).
- Load balancers route only to instances returning `200` from `/readyz`.
- Kubernetes: map `/healthz` to a liveness probe and `/readyz` to a readiness
  probe; because `/readyz` fails closed on backend loss, a store outage drains
  the pod from rotation without killing it.

## Bring up the reference stack

```bash
cd deploy/reference
cp .env.example .env      # set POSTGRES_PASSWORD and VINCTOR_PUBLIC_HOSTNAME
docker compose up -d --build
docker compose ps
```

Bootstrap keys and issue a grant as in
[preview-runbook.md](preview-runbook.md) (the commands are identical; only the
backend differs). Then smoke the topology:

```bash
# Through the HTTPS edge (Caddy blocks /metrics):
deploy/reference/smoke.sh --endpoint https://vinctor.example.com --metrics blocked
# localhost / internal CA:
deploy/reference/smoke.sh --endpoint https://localhost --insecure --metrics blocked
```

`smoke.sh` checks `/healthz`, `/readyz`, and the `/metrics` reachability
expectation, and fails closed (non-zero exit) on any unreachable endpoint or
unexpected status.

To confirm `/metrics` is actually reachable *inside* the network (it is not
host-resolvable, and the vinctor image has no curl), run the check from a
curl-equipped container attached to `vinctor-net`:

```bash
docker run --rm --network "${COMPOSE_PROJECT_NAME:-vinctor-reference}_vinctor-net" \
  -v "$PWD/deploy/reference/smoke.sh:/smoke.sh:ro" curlimages/curl:latest \
  sh /smoke.sh --endpoint http://vinctor:8765 --metrics open
```

After some audited activity (an enforce or a grant), verify the tamper-evidence
anchor is actually being written — this catches the fail-open case where the
sink path is unwritable and the stream is silently empty:

```bash
docker compose exec vinctor \
  sh -c 'test -s /data/chain-heads.jsonl && echo "anchor OK" || (echo "anchor EMPTY" >&2; exit 1)'
# or, if the file is visible on the host / in the same container as the script:
deploy/reference/smoke.sh --endpoint http://vinctor:8765 --anchor-file /data/chain-heads.jsonl
```

For the full authz path (permit + deny + audit lookup) — which also generates the
audited activity the anchor records — run `deploy/preview/smoke.py` with keys
against the same endpoint.

## What this does not provide

- a hosted/managed Vinctor service or multi-tenant cloud control plane
- database HA, replication, or disaster recovery (owned by your Postgres
  provider)
- credential broker, sandboxing/process isolation, or provider integrations
- an interactive login / session / approval UI

Production HA still depends on the database provider, network policy, secret
management, connection limits, backups, and the load balancer.
