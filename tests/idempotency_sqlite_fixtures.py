from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from vinctor_core.models import AuditEvent
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
        IdempotencyInvocation,
    )
    from vinctor_service.idempotency_sqlite import (
        SQLiteIdempotencyStore,
        SQLiteIdempotentMutationExecutor,
    )
    from vinctor_service.sqlite_pool import SQLiteServicePool

def configured_executor(
    database: Path,
    *,
    nonce_factory: Callable[[int], bytes] | None = None,
) -> tuple[
    SerializedSQLiteConnection,
    SQLiteIdempotencyStore,
    SQLiteIdempotentMutationExecutor,
]:
    from vinctor_service.idempotency_keyring import load_idempotency_keyring
    from vinctor_service.idempotency_sqlite import (
        SQLiteIdempotencyStore,
        SQLiteIdempotentMutationExecutor,
    )

    key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    connection = connect_sqlite(database)
    init_sqlite_schema(connection)
    store = SQLiteIdempotencyStore(
        connection,
        keyring=keyring,
        nonce_factory=nonce_factory,
    )
    store.audit_writer = SQLiteAuditWriter(connection)
    connection.execute(
        "UPDATE idempotency_cipher_key_versions "
        "SET first_seen_epoch = 0 "
        "WHERE version_label = 'primary' AND reserved_encryption_slots = 0"
    )
    connection.commit()
    return connection, store, SQLiteIdempotentMutationExecutor(store)


def configured_pool(
    database: Path,
    *,
    size: int = 2,
    connection_factory: Callable[[], SerializedSQLiteConnection] | None = None,
    lease_timeout_seconds: float = 10.0,
) -> SQLiteServicePool:
    from vinctor_service.idempotency_keyring import load_idempotency_keyring
    from vinctor_service.keys import SQLiteLocalKeyRepository
    from vinctor_service.sqlite import SQLiteV1Service
    from vinctor_service.sqlite_pool import SQLiteServicePool

    key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=keyring)
    keys = SQLiteLocalKeyRepository(connection)
    return SQLiteServicePool(
        database,
        primary_connection=connection,
        primary_service=service,
        primary_key_repository=keys,
        size=size,
        connection_factory=connection_factory,
        lease_timeout_seconds=lease_timeout_seconds,
    )


def invocation(
    *,
    key_hash: bytes = b"k" * 32,
    fingerprint: bytes = b"f" * 32,
) -> IdempotencyInvocation:
    from vinctor_service.idempotency_models import IdempotencyInvocation

    return IdempotencyInvocation(
        workspace_id="ws",
        principal="agent:a",
        operation="grant.issue.v1",
        key_hash=key_hash,
        request_fingerprint=fingerprint,
        max_terminal_ttl_seconds=86_400,
    )


def outcome(
    body: bytes = b'{"ok":true}',
    *,
    error_code: str | None = None,
    decision: str | None = None,
) -> CacheableTerminalOutcome:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
        HttpResponseObservation,
        PreSerializedHttpResponse,
    )

    return CacheableTerminalOutcome(
        response=PreSerializedHttpResponse(
            status_code=201,
            content_type="application/json",
            body=body,
            observation=HttpResponseObservation(error_code=error_code, decision=decision),
        )
    )


def count_rows(connection: SerializedSQLiteConnection, table: str) -> int:
    row = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()
    assert row is not None
    return int(row[0])


def audit_event(event_id: str = "evt_idempotency") -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        event_type="grant_issued",
        decision="permit",
        reason="grant_issued",
        workspace_id="ws",
        agent_id="agent:a",
        grant_id="grnt_idempotency",
        grant_ref="grt_idempotency",
        action="write",
        resource="grant/grt_idempotency",
        scope_attempted="write:grant/grt_idempotency",
        scope_matched="write:grant/*",
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
    )
