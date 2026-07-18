# Single-Node Preview Deployment

This runbook describes a preview-grade, single-node Vinctor deployment for one
early design partner. It creates a real HTTPS endpoint that can receive
`/v1/enforce` requests, but it is not a hosted SaaS product and does not claim
production readiness.

Use this only for low-volume preview traffic on a machine you control.

## Scope

This deployment provides:

- the existing `vinctor service serve` stdlib HTTP runtime
- SQLite state on a durable Docker volume
- Caddy TLS termination in front of the Vinctor service
- healthcheck-driven container restart behavior
- operator-managed key, grant, audit, backup, and restore procedures

This deployment does not provide:

- hosted managed service behavior
- high availability, replication, or autoscaling
- Postgres
- SIEM, metrics, or production observability
- production auth/session/user management
- credential broker behavior
- approval workflow UI
- sandboxing, raw interception, or provider integration
- official Claude, Codex, Hermes, or MCP runtime integrations

## Files

Preview deployment files live under `deploy/preview/`:

- `compose.yaml` - Vinctor service plus Caddy reverse proxy
- `Caddyfile` - TLS termination and reverse proxy config
- `.env.example` - non-secret configuration template
- `smoke.py` - health/enforce/audit smoke check

The `.env` file and raw keys must not be committed.

## Prerequisites

- Docker with Compose support
- a DNS name pointing to the preview host, or `localhost` for local TLS testing
- firewall rules that expose only Caddy's HTTP/HTTPS ports
- a secure out-of-band channel for sharing partner runtime secrets

## Start The Preview Stack

```bash
cd deploy/preview
cp .env.example .env
```

Edit `.env`:

```bash
VINCTOR_PREVIEW_HOSTNAME=vinctor-preview.example.com
VINCTOR_HTTP_PORT=80
VINCTOR_HTTPS_PORT=443
VINCTOR_LOG_LEVEL=info
```

Do not add `VINCTOR_WORKSPACE_KEY`, `VINCTOR_AGENT_KEY`, or
`VINCTOR_GRANT_REF` to `.env`.

Start the stack:

```bash
docker compose --env-file .env up -d --build
docker compose ps
```

Caddy terminates TLS and proxies to the internal Vinctor service container.
The Vinctor service container does not publish port `8765` directly.

Check health:

```bash
curl -sS https://vinctor-preview.example.com/healthz
```

For local `localhost` testing, Caddy uses a local certificate authority. Use
`curl -k` only for that local/internal certificate case.

## Bootstrap Operator And Agent Keys

`vinctor service serve` does not mint authority on startup. Mint keys with
operator commands inside the service container. Raw keys are printed once; store
them outside the repository immediately.

> WARNING: `operator keys rotate` is destructive on re-run. Each invocation
> mints a fresh key and revokes the previously active key of the same type
> (workspace) or the same agent. Run the bootstrap `rotate` commands below
> EXACTLY ONCE. Re-running `rotate` after you have already handed a key to a
> partner will revoke that key and silently break the partner runtime. Treat any
> later `rotate` as an intentional rotation (see "Key Rotation And Revocation"),
> not as a repeatable bootstrap step.

Before running `rotate`, check whether this database is already provisioned. If
an active workspace key (and an active agent key for `agent_partner`) already
exists, bootstrap is already done and you must NOT run `rotate` again:

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite --workspace-id ws_partner \
  operator keys list
```

A fresh database prints `no keys`. A provisioned database lists records with
`status=active`. Only proceed with the `rotate` commands when no active key of
the type you intend to mint exists.

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite --workspace-id ws_partner \
  operator keys rotate workspace

docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite --workspace-id ws_partner \
  operator keys rotate agent --agent-id agent_partner
```

Record:

- the raw workspace key for operator/admin use
- the raw agent key for the partner runtime

SQLite stores key hashes and metadata only. It cannot recover raw keys later.

Set issuer bounds for the partner agent before issuing a grant:

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite --workspace-id ws_partner \
  operator bounds set agent_partner --scope write:repo/preview/*
```

## Issue The Partner Grant Through The Service

Issue the partner grant through the HTTP service authority. Do not seed grants
with direct database insertion.

```bash
export VINCTOR_ENDPOINT="https://vinctor-preview.example.com"
export VINCTOR_WORKSPACE_KEY="wsk_..."

curl -sS "$VINCTOR_ENDPOINT/v1/grants" \
  -H "Content-Type: application/json" \
  -H "X-Workspace-Key: $VINCTOR_WORKSPACE_KEY" \
  -d '{
    "agent_id": "agent_partner",
    "scopes": ["write:repo/preview/*"],
    "ttl_seconds": 86400
  }'
```

Copy the returned `grant_ref`. The design partner needs:

```bash
export VINCTOR_ENDPOINT="https://vinctor-preview.example.com"
export VINCTOR_AGENT_KEY="aak_..."
export VINCTOR_GRANT_REF="grt_..."
```

If you registered a boundary for the partner runtime, also provide:

```bash
export VINCTOR_BOUNDARY_ID="bnd_..."
```

Do not send the workspace key to the partner runtime.

## Partner Secret Handoff

Share runtime values through a secure operator-controlled channel. Do not place
raw keys in GitHub, issue comments, logs, Docker images, Compose files, or
model-facing prompts.

The partner runtime should receive only:

- HTTPS endpoint
- agent key
- grant ref
- optional boundary id
- allowed action/resource expectations

## Restart And Persistence Check

Verify state survives a service restart:

```bash
docker compose restart vinctor
curl -sS https://vinctor-preview.example.com/healthz
```

Then run the smoke check from the repository root:

```bash
python deploy/preview/smoke.py \
  --endpoint "$VINCTOR_ENDPOINT" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --permit-action write \
  --permit-resource repo/preview/README.md \
  --deny-action write \
  --deny-resource repo/other/README.md
```

Use `--insecure-tls` only for localhost or internal-CA preview testing.

## Fail-Closed When Vinctor Is Unreachable

The preview posture is fail-closed: if the Vinctor service is down, or Caddy
cannot reach the backend, the partner runtime must not silently behave as if
every action were permitted. Authorization the runtime cannot obtain is denied,
not assumed.

The smoke check encodes this. If the endpoint refuses connections, times out, or
returns a non-`ok` health body, `smoke.py` exits non-zero and prints the failure
to stderr instead of reporting success. Verify it yourself by pointing the smoke
check at a closed port:

```bash
python deploy/preview/smoke.py \
  --endpoint http://127.0.0.1:1 \
  --agent-key unused --workspace-key unused --grant-ref unused
echo "exit=$?"
```

Expected: a `preview smoke failed:` line on stderr and `exit=1`. A success line
or `exit=0` here would mean the smoke check is not fail-closed; stop and fix it
before relying on the deployment.

Operationally, this means: keep Caddy's healthcheck-gated `depends_on` in place
so traffic is not proxied to an unhealthy backend, and ensure the partner
runtime treats a Vinctor enforce error as a deny, never as a default-permit.

## Backup And Restore

Create a consistent snapshot:

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite \
  operator storage backup --output /data/backups/vinctor-preview.sqlite --force

docker compose cp vinctor:/data/backups/vinctor-preview.sqlite ./vinctor-preview.sqlite
```

Restore from a snapshot:

```bash
docker compose stop vinctor
# docker cp writes the file root-owned with the host file's mode. This file
# holds plaintext pop_secret values and auth state — it must stay 0600, never
# chmod'd world-readable to work around the ownership mismatch.
docker compose cp ./vinctor-preview.sqlite vinctor:/data/restore-staging.sqlite
# Re-stage it at the ownership and mode the restore needs, with a
# narrowly-scoped root helper: this one-off invocation's only job is
# `install`, never the application or the restore itself.
docker compose run --rm --no-deps --user 0 vinctor \
  install -o 10001 -g 10001 -m 0600 \
  /data/restore-staging.sqlite /data/restore-source.sqlite
docker compose run --rm --no-deps --user 0 vinctor rm -f /data/restore-staging.sqlite
# The restore itself runs as the image's non-root user (uid 10001), which
# keeps the replaced database owned by the service user — do not add --user 0.
docker compose run --rm --no-deps vinctor \
  vinctor --db /data/vinctor.sqlite \
  operator storage restore --input /data/restore-source.sqlite --yes
docker compose start vinctor
```

Run the smoke check again after restore.

## Audit Export

Export operator audit as JSONL:

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  operator audit export --format jsonl --file /data/audit-export.jsonl

docker compose cp vinctor:/data/audit-export.jsonl ./audit-export.jsonl
```

Audit export is operator-facing. It must not include raw tool input, raw command
text, prompts, or model-facing reason strings.

## Key Rotation And Revocation

List key metadata:

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite --workspace-id ws_partner operator keys list
```

Revoke a key:

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite operator keys revoke lkey_...
```

Rotate the partner agent key:

```bash
docker compose exec vinctor \
  vinctor --db /data/vinctor.sqlite --workspace-id ws_partner \
  operator keys rotate agent --agent-id agent_partner
```

The replacement raw key is printed once. Rotation here is intentional: it
revokes the partner's current key, so re-hand the new raw key to the partner
runtime out-of-band immediately. This is the same command used at bootstrap, so
never re-run the bootstrap `rotate` steps unless you mean to rotate.

## Deferred GA Work

Before any GA deployment, revisit at least:

- production process/server choice
- Postgres or another managed durable store
- replication, HA, and disaster recovery objectives
- multi-tenant provisioning automation
- production identity, operator roles, and access review
- metrics, alerting, and SIEM integration
- release artifact publishing and upgrade policy

## Maintenance Notes

CONTEXT: The preview stack (compose + Caddy + smoke) and this runbook already
existed for a single early design partner. Two operational footguns and one
verification-scope gap needed closing.

WHAT THIS CHANGE DOES:

- Documents that bootstrap `operator keys rotate` is destructive on re-run (it
  revokes the prior active key) and must be run exactly once, with an
  `operator keys list` pre-check to detect an already-provisioned database.
- Documents the fail-closed posture when Vinctor is unreachable and adds a
  reproducible smoke-against-closed-port check; backs it with two tests in
  `tests/test_preview_deployment.py` asserting `run_smoke` raises and the CLI
  exits non-zero against a down endpoint.
- Records (here and in preview-validation.md) that real `docker compose up` plus
  full end-to-end smoke is FOUNDER-GATED: there is no Docker in the build/CI
  environment, so only the in-repo non-Docker tests are automatically proven.

NEXT STEPS:

- Founder-operated host: run the Docker-dependent validation steps and record
  evidence per preview-validation.md.
- Optional: have the partner runtime assert it treats any Vinctor enforce error
  as a deny (default-deny), not a default-permit, and capture that in its own
  integration check.
