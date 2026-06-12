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
docker compose cp ./vinctor-preview.sqlite vinctor:/data/restore-source.sqlite
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

The replacement raw key is printed once.

## Deferred GA Work

Before any GA deployment, revisit at least:

- production process/server choice
- Postgres or another managed durable store
- replication, HA, and disaster recovery objectives
- multi-tenant provisioning automation
- production identity, operator roles, and access review
- metrics, alerting, and SIEM integration
- release artifact publishing and upgrade policy
