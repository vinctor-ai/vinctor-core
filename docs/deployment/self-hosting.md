# Self-Hosting Vinctor Service

Vinctor currently supports a local developer service and a narrow
self-hostable service foundation. Hosted managed service behavior is future
work.

This document describes the single-node local/self-hostable prototype shape. It
does not claim production readiness.

## Current Boundary

The current self-hosting work is a foundation slice. It answers:

> Can an operator run the Vinctor service runtime against local SQLite state on
> a machine they control?

The answer is yes for a single-node prototype. The next work should turn this
foundation into explicit operator interfaces for setup, storage, keys, upgrade,
and runtime operations.

## Deployment Modes

| Mode | Status | Meaning |
| --- | --- | --- |
| Local developer service | Supported prototype | A developer starts Vinctor locally for demos, dogfooding, and hook testing. |
| Self-hostable service | Foundation supported | An operator can run the same SQLite-backed service on a machine they control. |
| Hosted managed service | Future | Not implemented in this repository. |

## What This Provides

- a SQLite-backed HTTP service runtime
- `GET /healthz`
- strict `POST /v1/enforce`
- workspace/admin routes for local policy, grants, requests, boundaries, and audit
- durable local key hashes in SQLite
- explicit configuration through CLI flags and a small set of environment variables
- optional Docker/Compose files for local self-hosting experiments

## What This Does Not Provide

- hosted Vinctor service
- production high availability
- multi-tenant cloud control plane
- production auth/session/user management
- credential broker
- sandbox or OS/process isolation
- approval workflow UI
- provider integrations
- prompt or content safety
- official Claude, Codex, or Hermes runtime claims

## Configuration

`vinctor service serve` reads CLI flags first, then environment variables.

| Field | CLI flag | Environment variable | Default |
| --- | --- | --- | --- |
| host | `--host` | `VINCTOR_HOST` | `127.0.0.1` |
| port | `--port` | `VINCTOR_PORT` | `8765` |
| SQLite DB path | `--db` | `VINCTOR_DB` | `.vinctor/vinctor.sqlite` |
| service mode | `--mode` | `VINCTOR_SERVICE_MODE` | `local` |
| log level | `--log-level` | `VINCTOR_LOG_LEVEL` | `info` |
| key storage mode | n/a | n/a | `sqlite_hashes` |

Valid service modes are `local` and `self_hosted`.

## Run Directly

Install locally:

```bash
.venv/bin/python -m pip install -e ".[dev]"
```

Run the service runtime:

```bash
vinctor service serve \
  --host 127.0.0.1 \
  --port 8765 \
  --db .vinctor/vinctor.sqlite \
  --mode self_hosted
```

Equivalent module form:

```bash
.venv/bin/python -m vinctor_service service serve \
  --host 127.0.0.1 \
  --port 8765 \
  --db .vinctor/vinctor.sqlite \
  --mode self_hosted
```

The command prints:

- listening URL
- mode
- database path
- log level
- a clear prototype warning

It does not print raw workspace keys, agent keys, or grant refs.

## Health Check

```bash
curl -sS http://127.0.0.1:8765/healthz
```

Expected response:

```json
{
  "status": "ok",
  "service": "vinctor-service",
  "mode": "self_hosted"
}
```

The health response intentionally omits secrets, raw keys, grant refs, database
paths, and internal configuration.

## Bootstrap And Hook Environment

The self-hostable runtime opens existing SQLite service state. It does not
mint authority by itself.

For local dogfooding, bootstrap with an explicit local flow first:

```bash
vinctor local start \
  --db .vinctor/vinctor.sqlite \
  --boundary-name codex-local
```

That command may print local test/dev exports:

```bash
export VINCTOR_ENDPOINT="http://127.0.0.1:8765"
export VINCTOR_AGENT_KEY="aak_..."
export VINCTOR_GRANT_REF="grt_..."
export VINCTOR_WORKSPACE_KEY="wsk_..."
export VINCTOR_BOUNDARY_ID="bnd_..."
```

Hooks still need:

- `VINCTOR_ENDPOINT` to know where to send checks
- `VINCTOR_AGENT_KEY` to authenticate agent-side request/enforce calls
- `VINCTOR_GRANT_REF` to identify the issued grant being consumed
- optional `VINCTOR_BOUNDARY_ID` for boundary audit context

The strict `/v1/enforce` request body remains:

```json
{
  "grant_ref": "grt_...",
  "action": "execute",
  "resource": "ci/test"
}
```

Boundary context belongs in the `X-Vinctor-Boundary-Id` header, not the body.

## Docker Compose

A minimal Compose file is included for local self-hosting experiments:

```bash
docker compose up --build
```

It mounts SQLite state at `/data/vinctor.sqlite` inside the container and
publishes port `8765`.

This is not a production deployment recipe. Operators remain responsible for:

- network exposure and firewall rules
- TLS or reverse proxy setup
- workspace and agent key distribution
- SQLite backup/restore
- host patching and process supervision
- access controls around the database volume

## Demo

Run:

```bash
python demo/self_hostable_service_demo.py
```

The demo:

1. bootstraps local SQLite state with an explicit local setup helper
2. starts the self-hostable service runtime against that DB
3. calls `/healthz`
4. calls `/v1/enforce` for a permit and a deny

Expected success line:

```text
ALL SELF-HOSTABLE SERVICE STEPS PASSED ✓
```

## Deferred Work

These items are intentionally deferred because the current slice only creates
the self-hostable runtime foundation.

### Operator Interfaces

- `vinctor operator storage backup` and `restore` for SQLite state
- `vinctor operator storage reset` for explicit local/dev resets
- `vinctor operator storage migrate` or `upgrade` for schema transitions
- `vinctor operator keys rotate` for workspace and agent key rotation
- `vinctor operator keys revoke` for disabling compromised or stale keys
- `vinctor operator service info` for mode, schema version, and safe runtime
  metadata

### Deployment And Runtime Operations

- TLS/reverse proxy guidance
- firewall and network exposure guidance
- process supervision guidance such as systemd or supervisor examples
- log format and operational log-level guidance
- Docker image publishing and tagged release artifacts
- backup/restore runbook for mounted SQLite volumes

### Production Hardening

- production auth/session/user management
- managed identity integration
- high availability and replication strategy
- multi-tenant cloud control plane
- hosted managed service

Until these exist, use the wording "self-hostable foundation" or
"single-node self-hostable prototype", not "production-ready self-hosted
Vinctor".
