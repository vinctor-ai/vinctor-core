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

For a concrete design-partner preview layout with Caddy TLS termination, see
[Single-Node Preview Deployment](preview-runbook.md).

## Container Images And Releases

`.github/workflows/release.yml` cuts a release when you push a version tag:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Using the workflow's automatic `GITHUB_TOKEN` (no extra credentials), the tag build:

- builds the sdist + wheel and attaches them to the GitHub Release, and
- builds and pushes the container image to GHCR as
  `ghcr.io/vinctor-ai/vinctor-core:<version>` and `:latest`.

Pull and run the published image (the `CMD` is `vinctor service serve`):

```bash
docker run -p 8765:8765 -v vinctor-data:/data \
  ghcr.io/vinctor-ai/vinctor-core:0.2.0
```

A `workflow_dispatch` run is a build-only smoke check (it does not push or publish).

`vinctor-core` 0.2.0 is published on PyPI. For future tagged releases, PyPI
publishing remains controlled by the opt-in release configuration:

1. Set the repository variable `PUBLISH_PYPI=true`.
2. Create a GitHub Environment named `pypi` (the publish job declares
   `environment: pypi`, so the job will not start until it exists; optionally add
   required reviewers to gate publishes).
3. Configure [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/)
   for this repo (recommended — no stored token), or add a `PYPI_API_TOKEN` secret
   and pass it to the publish step (see the commented `with:` block in
   `release.yml`).

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
.venv/bin/python -m pip install vinctor-core          # from PyPI
# …or, when serving from this checkout (development):
# .venv/bin/python -m pip install -e ".[dev]"
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

`local start` prints these exports and then **keeps running as a foreground
server** — it does not return on its own. Use it once to mint and copy the keys,
then press Ctrl+C and run the persistent service with `vinctor service serve`
against the same `--db`. (For a full host setup, see
[Operational Runbooks → First-Time Setup](operational-runbooks.md#first-time-setup).)

The exports it prints:

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

## Operator Storage And Service Info

These operator commands manage the local SQLite state that backs a self-hosted
Vinctor service. They operate on the database file directly, so they:

- do **not** require a running HTTP service (run them while `serve` is stopped),
- never print raw workspace/agent keys or key hashes,
- read and write only the local SQLite file you point them at.

The database stores only key **hashes** and metadata (see
[ADR 0002](../decisions/0002-durable-local-key-storage.md)), so a backup file
carries no recoverable secrets.

### When to use which command

| Goal | Command |
| --- | --- |
| Check what mode/port/schema a deployment is on, before or after bootstrap | `operator service info` |
| Take a point-in-time snapshot of the database before an upgrade or risky change | `operator storage backup` |
| Restore the database from a snapshot | `operator storage restore` |
| Wipe a local/dev database and start from an empty schema | `operator storage reset` |
| Confirm the on-disk schema is current after a package upgrade | `operator storage migrate` |
| See which local keys exist (masked metadata) | `operator keys list` |
| Disable a compromised or stale key | `operator keys revoke` |
| Replace a workspace or agent key (prints the new raw key once) | `operator keys rotate` |

`operator service info` is the single safe-metadata command. (An earlier
`operator storage info` has been folded into it.)

### Flag ordering

`--db` and `--json` are **global** flags: place them before the role, not after
the subcommand. Use `vinctor --db <path> operator ...`, not
`vinctor operator ... --db <path>` (the latter is rejected as an unrecognized
argument). Subcommand-specific flags like `--output`, `--force`, and `--yes`
come after the subcommand.

### Database path resolution

These commands act on a single SQLite file. How that path is resolved differs on
purpose:

- **`service info`** resolves the path from `--db`, then `VINCTOR_DB`, then the
  default `.vinctor/vinctor.sqlite`. It is safe to run with no arguments as a
  pre-flight check; it never creates the file.
- **`storage backup`/`reset`/`restore`/`migrate` and the `keys` commands**
  require an explicit database via `--db` or `VINCTOR_DB`. They do **not** fall
  back to the default path, so a destructive `reset`/`restore` can never touch
  an unintended default database by accident.

### `operator service info`

Reports safe runtime and storage metadata from configuration plus local SQLite.

```bash
vinctor --db .vinctor/vinctor.sqlite operator service info
```

Text output:

```text
service mode=local host=127.0.0.1 port=8765 db=.vinctor/vinctor.sqlite schema_version=2 key_storage=sqlite_hashes
```

JSON output (`--json`):

```json
{
  "db_path": ".vinctor/vinctor.sqlite",
  "host": "127.0.0.1",
  "key_storage_mode": "sqlite_hashes",
  "mode": "local",
  "port": 8765,
  "schema_version": 2,
  "schema_versions": [1, 2]
}
```

- `mode`, `host`, `port` come from the same `VINCTOR_SERVICE_MODE`,
  `VINCTOR_HOST`, `VINCTOR_PORT` configuration used by `vinctor service serve`.
- `schema_version` is the highest applied schema version (a scalar);
  `schema_versions` is the full list of applied versions. Use `schema_version`
  for a simple "what version is this DB" check.
- If the database does not exist yet, `schema_version` is `null`
  (shown as `schema_version=-` in text mode), `schema_versions` is `[]`, and
  **no database is created**.

### `operator storage backup`

Writes a consistent snapshot of the database to a file.

```bash
vinctor --db .vinctor/vinctor.sqlite operator storage backup \
  --output backups/vinctor-$(date +%Y%m%d).sqlite
```

Text output:

```text
backup db=.vinctor/vinctor.sqlite output=backups/vinctor-20260611.sqlite bytes=102400
```

JSON output (`--json`):

```json
{
  "bytes": 102400,
  "db_path": ".vinctor/vinctor.sqlite",
  "output_path": "backups/vinctor-20260611.sqlite",
  "schema_versions": [1, 2]
}
```

- The snapshot uses the SQLite backup API, so it is consistent even if a
  service holds the database open. You do not have to stop the service to back
  up, but a quiesced database gives the cleanest snapshot.
- `--output` refuses to overwrite an existing file unless `--force` is passed,
  to prevent clobbering a previous backup.
- Parent directories of `--output` are created automatically.

### `operator storage reset`

Removes the database file and recreates an empty, initialized schema.

```bash
vinctor --db .vinctor/vinctor.sqlite operator storage reset --yes
```

Text output:

```text
reset db=.vinctor/vinctor.sqlite schema_versions=1,2
```

JSON output (`--json`):

```json
{
  "db_path": ".vinctor/vinctor.sqlite",
  "reset": true,
  "schema_versions": [1, 2]
}
```

- `--yes` is **required**. Without it the command refuses and changes nothing.
- Reset takes **no implicit backup**. Run `storage backup` first if you want
  one.
- **Stop the running service first.** Resetting a database that a live service
  has open leaves that process pointing at a now-stale file handle.
- This is a local/development convenience. The database is always
  operator-created and never committed to the repository.

### `operator storage restore`

Replaces the database with a snapshot produced by `storage backup`.

```bash
vinctor --db .vinctor/vinctor.sqlite operator storage restore \
  --input backups/vinctor-20260611.sqlite --yes
```

JSON output (`--json`):

```json
{
  "db_path": ".vinctor/vinctor.sqlite",
  "input_path": "backups/vinctor-20260611.sqlite",
  "restored": true,
  "schema_versions": [1, 2]
}
```

- `--yes` is **required** (restore overwrites the live database).
- The input is **validated before anything is replaced**: if it is missing or
  not a usable Vinctor SQLite snapshot, the command errors and the existing
  database is left untouched.
- **Stop the running service first**, then restore, then restart.

### `operator storage migrate`

Applies schema setup explicitly and reports the resulting versions. The schema
is applied on open, so this is idempotent and never destroys data; run it after
upgrading the package to confirm the on-disk schema is current.

```bash
vinctor --db .vinctor/vinctor.sqlite operator storage migrate
```

```text
migrate db=.vinctor/vinctor.sqlite schema_versions=1,2
```

### `operator keys list`

Lists local key records as **masked metadata** for the workspace selected by
`--workspace-id` (default `ws_local`). Never prints raw keys or key hashes.

```bash
vinctor --db .vinctor/vinctor.sqlite --workspace-id ws_local operator keys list
```

JSON output (`--json`):

```json
{
  "keys": [
    {
      "key_id": "lkey_...",
      "key_type": "workspace",
      "workspace_id": "ws_local",
      "agent_id": null,
      "key_prefix": "wsk_",
      "status": "active",
      "created_at": "2026-06-10T12:00:00+00:00",
      "last_used_at": null,
      "revoked_at": null
    }
  ]
}
```

`key_id` is the stable handle used by `keys revoke`. `key_prefix` is only the
key-type prefix (`wsk_`/`aak_`), not a recoverable secret.

### `operator keys revoke`

Revokes a key by its `key_id` (from `keys list`). Revoked keys resolve as
unauthenticated, returning the generic `401 authentication_required`.

```bash
vinctor --db .vinctor/vinctor.sqlite operator keys revoke lkey_...
```

```text
revoked key lkey_... status=revoked
```

### `operator keys rotate`

Mints a replacement key and revokes the previously active key(s) of that type.
The new raw key is printed **once** — store it immediately, because SQLite keeps
only the hash and it cannot be recovered.

```bash
# Rotate the workspace/admin key:
vinctor --db .vinctor/vinctor.sqlite --workspace-id ws_local operator keys rotate workspace

# Rotate the read-only workspace auditor key:
vinctor --db .vinctor/vinctor.sqlite --workspace-id ws_local operator keys rotate auditor

# Rotate a specific agent's key:
vinctor --db .vinctor/vinctor.sqlite --workspace-id ws_local operator keys rotate agent \
  --agent-id agent_local
```

Text output (the raw key is shown once):

```text
rotated workspace key key_id=lkey_... revoked=lkey_old
raw_key=wsk_...
# Store this raw key now; it cannot be recovered from SQLite.
```

JSON output (`--json`) includes the raw key **only** for `rotate` — never for
`list`:

```json
{
  "agent_id": null,
  "key_id": "lkey_new",
  "key_type": "workspace",
  "raw_key": "wsk_...",
  "revoked_key_ids": ["lkey_old"],
  "workspace_id": "ws_local"
}
```

Rotating the workspace or auditor key revokes prior active keys of that same
type only; rotating an agent key revokes prior active keys for that agent id
only. Auditor keys (`auk_…`) are accepted only on the audit read endpoints via
`X-Auditor-Key`; they cannot perform operator mutations. After rotating,
distribute the new key to the relevant caller and update its environment.

### Flags

| Flag | Commands | Required | Meaning |
| --- | --- | --- | --- |
| `--db <path>` | all (backup/reset/restore/migrate/keys require it; info falls back) | backup, reset, restore, migrate, keys | SQLite database path. Also read from `VINCTOR_DB`. |
| `--workspace-id <id>` | keys | no (default `ws_local`) | Workspace scope for key list/rotate. |
| `--output <path>` | backup | yes | Snapshot destination file. |
| `--input <path>` | restore | yes | Snapshot source file. |
| `--force` | backup | no | Overwrite an existing `--output` file. |
| `--yes` | reset, restore | yes | Confirm the destructive operation. |
| `--agent-id <id>` | keys rotate agent | yes | Agent whose key is rotated. |
| `--json` / `-o json` | all | no | Emit JSON instead of text (global flag). |

The snapshot commands use `--output` (backup) and `--input` (restore) for binary
database artifacts. Document-style commands (`policy apply/export`,
`audit export`) use `--file`. This `--output`/`--input` vs `--file` split is
intentional: snapshot files in, snapshot files out.

### Exit codes

| Situation | Exit code |
| --- | --- |
| Success | `0` |
| `reset` / `restore` without `--yes` | `2` |
| `backup --output` points at an existing file without `--force` | `2` |
| `backup` source database missing | `2` |
| `restore --input` missing or not a valid snapshot | `2` |
| `keys revoke` with an unknown `key_id` | `2` |
| `--db` required but not provided | `2` |

These map to the shared CLI exit codes documented in
[`docs/cli-design.md`](../cli-design.md) (`2` = usage error).

### Backup / restore lifecycle

```bash
# 1. Stop the service (Ctrl+C on `vinctor service serve`, or `docker compose down`).

# 2. Snapshot the current database.
vinctor --db .vinctor/vinctor.sqlite operator storage backup \
  --output backups/vinctor-before-change.sqlite

# 3. (optional) Reset to an empty schema for a clean dev run.
vinctor --db .vinctor/vinctor.sqlite operator storage reset --yes

# 4. Restore from a snapshot (validates the input before replacing the DB).
vinctor --db .vinctor/vinctor.sqlite operator storage restore \
  --input backups/vinctor-before-change.sqlite --yes

# 5. Start the service again.
vinctor service serve --db .vinctor/vinctor.sqlite --mode self_hosted
```

## Docker Compose

A minimal Compose file is included for local self-hosting experiments:

```bash
docker compose up --build
```

It mounts SQLite state at `/data/vinctor.sqlite` inside the container and
publishes port `8765`.

This is not a production deployment recipe. Operators remain responsible for
network exposure, TLS, key distribution, backup/restore, host patching, process
supervision, and database-volume access controls. See
[Operational Runbooks](operational-runbooks.md) for starting-point recipes
(reverse proxy/TLS, firewall, systemd, logs, and SQLite/volume backup).

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

The storage (`backup`/`reset`/`restore`/`migrate`), `service info`, and `keys`
(`list`/`revoke`/`rotate`) commands are now implemented — see
[Operator Storage And Service Info](#operator-storage-and-service-info).
Remaining operator-interface follow-ups:

- Real schema migrations beyond the current version markers (the `migrate`
  command is in place; it becomes meaningful once a v3+ migration exists).
- Richer key listing filters and `last_used` reporting as the local key set
  grows.

### Deployment And Runtime Operations

Starting-point runbooks for TLS/reverse proxy, firewall, systemd supervision,
logs/observability, and SQLite/volume backup are documented in
[Operational Runbooks](operational-runbooks.md). Still deferred:

- managed log/metrics aggregation, alerting, and production SLOs beyond the
  shipped opt-in structured access log and Prometheus endpoint
- automated fleet rollout, rollback, and registry-promotion policy beyond the
  published tagged package and container-image artifacts

### Production Hardening

- production auth/session/user management
- managed identity integration
- high availability and replication strategy
- multi-tenant cloud control plane
- hosted managed service

Until these exist, use the wording "self-hostable foundation" or
"single-node self-hostable prototype", not "production-ready self-hosted
Vinctor".
