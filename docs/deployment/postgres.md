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

## Deliberately not yet switched

Local key storage, grant-request/approval workflows, subject tokens, agent
enforcement settings, and boundary administration remain SQLite-backed. The
local CLI therefore continues to select SQLite. Promoting Postgres to the
default service runtime requires those repositories plus migration and backup
runbooks; this slice does not imply that cutover.

## Integration contract

Set `VINCTOR_TEST_POSTGRES_DSN` to run the real database tests. CI provisions
Postgres 16 and verifies grant lifecycle, enforce audit persistence,
observe-to-infer behavior, and concurrent audit-chain serialization.
