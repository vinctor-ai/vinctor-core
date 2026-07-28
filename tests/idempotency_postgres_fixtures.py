from __future__ import annotations

import base64
from collections.abc import Callable
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from vinctor_core.models import AuditEvent
from vinctor_service.postgres import (
    PostgresAuditWriter,
    connect_postgres,
    init_postgres_schema,
)

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
        IdempotencyInvocation,
    )
    from vinctor_service.idempotency_postgres import (
        PostgresIdempotencyStore,
        PostgresIdempotentMutationExecutor,
    )
    from vinctor_service.postgres_connection import SerializedPostgresConnection

def configured_postgres_executor(
    dsn: str,
    *,
    nonce_factory: Callable[[int], bytes] | None = None,
) -> tuple[
    SerializedPostgresConnection,
    PostgresIdempotencyStore,
    PostgresIdempotentMutationExecutor,
]:
    from vinctor_service.idempotency_keyring import load_idempotency_keyring
    from vinctor_service.idempotency_postgres import (
        PostgresIdempotencyStore,
        PostgresIdempotentMutationExecutor,
    )

    key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    connection = connect_postgres(dsn)
    init_postgres_schema(connection)
    store = PostgresIdempotencyStore(
        connection,
        keyring=keyring,
        nonce_factory=nonce_factory,
    )
    store.audit_writer = PostgresAuditWriter(connection)
    return connection, store, PostgresIdempotentMutationExecutor(store)


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


def count_rows(connection: SerializedPostgresConnection, table: str) -> int:
    row = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()
    assert row is not None
    return int(row[0])


def schema_versions(
    connection: SerializedPostgresConnection,
) -> tuple[int, ...]:
    rows = connection.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    return tuple(int(row[0]) for row in rows)


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
