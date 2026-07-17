# Postgres service backend

The optional Postgres backend provides durable control-plane state for a
multi-instance Vinctor service. It implements the existing repository contracts
rather than adding database checks to the deterministic core.

## Supported

- schema bootstrap with `init_postgres_schema`
- grant insert, lookup, workspace listing, and revocation
- `/v1/enforce` through `PostgresV1Service`
- `/v1/observe` and audit-backed policy inference
- boundary registry and boundary-required enforcement
- agent enforcement settings (`require_boundary`, `require_subject_token`, `require_pop`)
- agent issuable-scope bounds and auto-approval rules
- local workspace, agent, and PEP key hashes
- grant-request create, list, approve, reject, and auto-approve state
- subject-token mint, lookup, list, and revocation state
- durable cross-instance PoP nonce replay prevention
- append-only policy versions and exact policy rollback
- durable audit lookup/filtering
- one global tamper-evident audit chain serialized across service instances
- the complete `vinctor service serve` HTTP surface and `/readyz` probe

Install and connect:

```bash
python -m pip install "vinctor-core[postgres]"
```

```python
from vinctor_service import PostgresV1Service, connect_postgres

connection = connect_postgres("postgresql://vinctor:secret@db/vinctor")
service = PostgresV1Service(connection)
```

Each process owns one connection. The built-in threaded HTTP runtime serializes
complete transactions on that connection; separate processes coordinate through
Postgres constraints and advisory locks.

## Run the service

The decision-store startup path can now select and verify either backend from
the shared runtime configuration:

```bash
export VINCTOR_STORAGE_BACKEND=postgres
export VINCTOR_POSTGRES_DSN='postgresql://vinctor:secret@db/vinctor'
vinctor service serve --host 0.0.0.0 --mode self_hosted
```

Startup initializes the supported schema, runs a `SELECT 1` readiness probe,
The startup banner prints only `postgres`, never the DSN.

The HTTP runtime also exposes separate liveness and readiness contracts:

- `/healthz` reports whether the process is alive.
- `/readyz` reports whether the active durable-store connection accepts
  `SELECT 1`; it fails closed with `503` without exposing connection details.

Load balancers should route traffic only to instances returning `200` from
`/readyz`.

## Bootstrap keys

The service does not mint authority on startup. Provision initial keys through
the repository from a trusted administrative process; only hashes are stored:

```python
from vinctor_service.postgres import connect_postgres, init_postgres_schema
from vinctor_service.postgres_control import PostgresLocalKeyRepository

connection = connect_postgres("postgresql://vinctor:secret@db/vinctor")
init_postgres_schema(connection)
keys = PostgresLocalKeyRepository(connection)
created = keys.create_workspace_key(workspace_id="ws_main")
print(created.raw_key)  # show once, then place it in the caller's secret store
connection.close()
```

Do not log the returned raw key or store it in Postgres.

## Backup and restore

Back up the database with the platform's managed snapshot feature or `pg_dump`.
Restore into an empty database with `pg_restore`, then start one Vinctor instance
and wait for `/readyz` before scaling out. Schema initialization is idempotent,
but backups and restores must cover all Vinctor tables together so the audit
chain, grants, tokens, and replay state remain consistent.

Postgres enables shared state and horizontal service processes; production HA
still depends on the database provider, TLS/authentication, secret management,
connection limits, backups, and a load balancer. The built-in server is a
self-hosted runtime, not a managed HA control plane.

## Integration contract

Set `VINCTOR_TEST_POSTGRES_DSN` to run the real database tests. CI provisions
Postgres 16 and verifies key resolution, grant-request and subject-token
lifecycle, cross-instance replay prevention, complete runtime startup, shared
state between service instances, enforce audit persistence, observe-to-infer
behavior, policy rollback, and concurrent audit-chain serialization.
