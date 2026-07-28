from __future__ import annotations

import base64
from pathlib import Path
from typing import TYPE_CHECKING

from idempotency_sqlite_fixtures import (
    count_rows,
    invocation,
    outcome,
)
from idempotency_sqlite_store_models import (
    CompletedResultSeed,
    ExpiredHistoricalReuseOutcome,
)
from idempotency_sqlite_store_seed import _seed_completed_result

from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import (
    IdempotencyResultUnavailable,
)
from vinctor_service.sqlite_txn import connect_sqlite

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
    )

def exercise_expired_historical_key_reuse(
    database: Path,
) -> ExpiredHistoricalReuseOutcome:
    from vinctor_service.idempotency_sqlite import (
        SQLiteIdempotencyStore,
        SQLiteIdempotentMutationExecutor,
    )
    from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema

    old = base64.b64encode(b"o" * 32).decode("ascii")
    new = base64.b64encode(b"n" * 32).decode("ascii")
    old_active = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"old":"{old}","new":"{new}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "old",
        }
    )
    new_only = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"new":"{new}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "new",
        }
    )
    connection = connect_sqlite(database)
    init_sqlite_schema(connection)
    old_store = SQLiteIdempotencyStore(connection, keyring=old_active)
    _seed_completed_result(connection, old_store, CompletedResultSeed(outcome(), 0))
    store = SQLiteIdempotencyStore(connection, keyring=new_only)
    store.audit_writer = SQLiteAuditWriter(connection)
    executor = SQLiteIdempotentMutationExecutor(store)
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome(b'{"fresh":true}')

    try:
        try:
            executor.execute(invocation(), mutation)
        except IdempotencyResultUnavailable:
            unavailable = True
        else:
            unavailable = False
        return ExpiredHistoricalReuseOutcome(
            unavailable=unavailable,
            callback_count=calls,
            result_count=count_rows(connection, "idempotency_results"),
            reservation_count=count_rows(connection, "idempotency_cipher_nonces"),
        )
    finally:
        connection.close()
