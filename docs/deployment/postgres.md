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

The extra is required only for this backend. A base `pip install vinctor-core`
is a complete SQLite deployment and is covered by CI's `bare-install` job; if
you select Postgres without the extra, `connect_postgres` raises
`PostgresDriverUnavailable` and `vinctor service serve` exits 5 with
``error: Postgres support requires `pip install vinctor-core[postgres]` ``. It
never falls back to SQLite, and the error discloses no DSN.

```python
from vinctor_service import PostgresV1Service, connect_postgres

connection = connect_postgres("postgresql://vinctor:secret@db/vinctor")
service = PostgresV1Service(connection)
```

Each process owns one connection. The built-in threaded HTTP runtime serializes
complete transactions on that connection; separate processes coordinate through
Postgres constraints and advisory locks. A lost connection is replaced under
that same process lock with bounded attempts and backoff before a later
operation. The operation that observed the loss is never replayed, because its
write or commit outcome may be ambiguous.

## Run the service

The decision-store startup path can now select and verify either backend from
the shared runtime configuration:

```bash
export VINCTOR_STORAGE_BACKEND=postgres
export VINCTOR_POSTGRES_DSN='postgresql://vinctor:secret@db/vinctor'
vinctor service serve --host 0.0.0.0 --mode self_hosted
```

Startup initializes the supported schema and runs a `SELECT 1` readiness probe.
The startup banner prints only `postgres`, never the DSN.

The HTTP runtime also exposes separate liveness and readiness contracts:

- `/healthz` is process liveness only. It performs no database operation, so a
  Postgres outage does not change it. Wire it to a liveness probe.
- `/readyz` reports whether the active durable-store connection accepts
  `SELECT 1`; it fails closed with `503` without exposing connection details.
  The probe is bounded (`VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS`, default 2s)
  and single-flight, so a hung backend cannot hold `/readyz` open and a probe
  flood produces at most one concurrent backend query. Raise the bound if the
  probe — which runs the idempotency-readiness queries as well as `SELECT 1` —
  can exceed it on a healthy but busy store; the same value is the
  `connect_timeout` and `statement_timeout` on the probe's connection.
  Readiness uses connections of its own, so it neither queues behind enforce
  traffic on the shared connection nor holds it. Size `max_connections` for
  **up to 5 extra sessions per service process**, not one: probes overlap
  whenever a wedged one is replaced, each overlapping probe opens its own
  session, and the abandoned-worker cap is 4. In steady state exactly one is
  open, and it is opened on first use.

  Readiness also probes the **serving** connection with a single `SELECT 1`,
  because the store being reachable does not mean this process can use it — and
  that probe is what reconnects a serving connection whose backend died. A
  drained instance receives no enforce requests, so nothing else would.

### What bounds a wedged readiness probe, and where it does not

| Mechanism | Enforced by | Covers a black-holed socket? |
|---|---|---|
| `statement_timeout` | the server | No — needs the server reachable |
| TCP keepalives | the kernel | No — do not fire while data is unacknowledged |
| `connect_timeout` | libpq | Handshake only |
| `cancel_safe(timeout=)` | psycopg | **Only on libpq 17+**; below that the argument is discarded and it falls back to a blocking `PQcancel` |
| `tcp_user_timeout` | the kernel | Yes — **Linux only**; accepted and ignored elsewhere, rejected before libpq 12 |
| the readiness deadline | Vinctor | Always: it bounds how long Vinctor *waits*, never how long the driver runs |

**A bounded query cancellation is required** — `Connection.cancel_safe()`,
which needs psycopg 3.2+ *and* libpq 17+ — and the service refuses to start
without it. It asks `psycopg.capabilities.has_cancel_safe(check=True)` rather
than reading a version number: psycopg 3.1 against libpq 18 passes a libpq check
and still has no such method.
That is what makes `cancel_safe`'s timeout real, and reclamation with it: a
wedged readiness probe is ended by cancelling it, and cancellation travels over
a new connection, so it lands as soon as the database is reachable. **This works
on every platform**, not only Linux.

`tcp_user_timeout` is a Linux-only refinement on top, and it is worth being
precise about what it adds: it bounds how quickly a black-holed socket *fails*,
not whether recovery happens. Recovery rests on the cancel. On a non-Linux host
a wedged session is held longer before the kernel gives up on it; readiness
still recovers when the database does.

A process that never regains contact with its database keeps up to 5 probe
worker threads and sessions, plus the reclaimer's single thread, until it is
restarted. Cancellation adds no threads of its own: the sweep runs inline on the
reclaimer, bounded by the driver. Size database sessions from the probe-worker
count.

Vinctor never waits past its own deadline, so `/readyz` answers on time on every
host regardless.

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

## Schema upgrades

PostgreSQL migration 8 adds the authoritative encrypted idempotency-result
schema. Upgrading from migration 7 requires a maintenance window:

1. Stop every Vinctor service replica, worker, and other database writer.
2. Take a complete managed snapshot or `pg_dump` and verify a restore into an
   empty drill database before proceeding.
3. Deploy one target-version instance and let schema initialization apply
   migration 8 while all other writers remain stopped.
4. Verify `schema_migrations` contains exactly the contiguous versions 1 through
   8, then start only target-version instances.

Do not run old and new binaries against the database at the same time. Rollback
after migration 8 is restore-only: stop every writer and restore the complete
verified migration-7 snapshot. Deleting migration row 8, dropping the new tables,
or editing them in place is not a supported downgrade and can invalidate replay
state or the audit chain.

## Encrypted idempotency key lifecycle

Inject `VINCTOR_IDEMPOTENCY_KEYRING_JSON` and
`VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION` from the deployment secret manager. Do not
place the raw JSON or DSN on a command line. `vinctor operator idempotency` reads the
same runtime configuration as the service and exposes only `status`, `write-disable`,
`drain-complete`, and `retire`.

For PostgreSQL, deploy the old and new decrypt keys together with the new label active,
then:

1. require every replica's `/readyz` probe to pass;
2. run `operator idempotency status`;
3. run `write-disable --version <old> --reason rotation`;
4. stop or drain every old writer and verify the external deployment state;
5. run `drain-complete --version <old> --confirm-no-active-writers`;
6. wait for PostgreSQL time to reach the recorded drain epoch plus `86,400 + 300`
   seconds;
7. run `retire --version <old> --confirm-removal-window`, verify the persistent
   tombstone/final slot count, restart and recheck readiness, then remove the old key
   bytes from external injection.

Every keyed PostgreSQL service automatically holds the database advisory writer lock
for its active key version for its full lifetime. A serialized replacement acquires
that version's shared lock and revalidates authoritative readiness before publication.
Drain and retirement take the historical target's exclusive lock, so old-version
writers in other processes and recovered generations block those operations while a
replacement-only writer does not. Ambiguous lifecycle acknowledgements recover through
a fresh authoritative connection under the same target exclusion. The active label is
never accepted as the historical target. Retirement checks the unexpired-result count
internally and refuses while any remain. Garbage collection uses PostgreSQL database
time, locks candidates with `FOR UPDATE SKIP LOCKED`, and deletes at most 100 expired
result rows per transaction. It never deletes nonce reservations or version tombstones.

Startup verifies exact reservation counts. Hot-path readiness uses the bounded registry
counter and fails closed for missing historical decrypt keys, immutable commitment
mismatch, unknown unexpired versions, or a disabled/retired active version. Status and
errors omit the keyring and DSN.

## Integration contract

Set `VINCTOR_TEST_POSTGRES_DSN` to run the real database tests. CI provisions
Postgres 16 and verifies key resolution, encrypted-result lifecycle and GC,
grant-request and subject-token lifecycle, cross-instance replay prevention,
complete runtime startup, shared state between service instances, enforce audit
persistence, observe-to-infer behavior, policy rollback, and concurrent
audit-chain serialization.
