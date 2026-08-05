from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from vinctor_service.idempotency_readiness import sqlite_idempotency_ready
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteServiceSharedState, SQLiteV1Service
from vinctor_service.sqlite_txn import SerializedSQLiteConnection


@dataclass(slots=True)
class SQLiteRequestContext:
    connection: SerializedSQLiteConnection
    service: SQLiteV1Service
    key_repository: SQLiteLocalKeyRepository
    generation: int
    healthy: bool = True
    closed: bool = False


def build_sqlite_request_context(
    connection_factory: Callable[[], SerializedSQLiteConnection],
    shared_state: SQLiteServiceSharedState,
    generation: int,
) -> SQLiteRequestContext:
    connection = connection_factory()
    service: SQLiteV1Service | None = None
    try:
        service = SQLiteV1Service(
            connection,
            initialize_schema=False,
            shared_state=shared_state,
        )
        service.assert_pool_state_contract()
        key_repository = SQLiteLocalKeyRepository(connection)
        if not sqlite_idempotency_ready(connection, service.idempotency_keyring):
            raise RuntimeError("SQLite replacement readiness check failed")
    except BaseException:
        if service is not None:
            service.close()
        connection.close()
        raise
    return SQLiteRequestContext(
        connection,
        service,
        key_repository,
        generation,
    )
