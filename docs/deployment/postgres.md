# Postgres storage foundation

The optional Postgres backend is the first storage abstraction slice for a
multi-instance Vinctor service. It implements the existing grant repository and
audit writer contracts rather than adding database checks to the deterministic
core.

## Supported in this slice

- schema bootstrap with `init_postgres_schema`
- grant insert, lookup, workspace listing, and revocation
- `/v1/enforce` through `PostgresV1Service`
- `/v1/observe` and audit-backed policy inference
- durable audit lookup/filtering
- one global tamper-evident audit chain serialized across service instances

Install and connect:

```bash
python -m pip install "vinctor-core[postgres]"
```

```python
from vinctor_service import PostgresV1Service, connect_postgres

connection = connect_postgres("postgresql://vinctor:secret@db/vinctor")
service = PostgresV1Service(connection)
```

Each process should own its connection or pool lease. Do not share one psycopg
connection concurrently between worker threads.

## Runtime selection foundation

The decision-store startup path can now select and verify either backend from
the shared runtime configuration:

```bash
export VINCTOR_STORAGE_BACKEND=postgres
export VINCTOR_POSTGRES_DSN='postgresql://vinctor:secret@db/vinctor'
```

```python
import os

from vinctor_service import load_service_runtime_config, prepare_decision_storage

storage = prepare_decision_storage(load_service_runtime_config(env=os.environ))
assert storage.is_ready()
```

Startup initializes the supported schema, runs a `SELECT 1` readiness probe,
and closes the connection if either step fails. SQLite remains the default.

## Deliberately not yet switched

Local key storage, grant-request/approval workflows, subject tokens, agent
enforcement settings, and boundary administration remain SQLite-backed. The
local CLI therefore continues to select SQLite. Promoting Postgres to the
default service runtime requires those repositories plus migration and backup
runbooks. `vinctor service serve` rejects a Postgres selection explicitly until
that control-plane migration is complete instead of starting a partial service.

## Integration contract

Set `VINCTOR_TEST_POSTGRES_DSN` to run the real database tests. CI provisions
Postgres 16 and verifies grant lifecycle, enforce audit persistence,
observe-to-infer behavior, and concurrent audit-chain serialization.
