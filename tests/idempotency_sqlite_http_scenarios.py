from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from idempotency_http_fixtures import NOW

from vinctor_core import Grant
from vinctor_service import AutoApprovalRule, GrantRequest
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite


@dataclass(frozen=True, slots=True)
class PersistedCounts:
    grants: int
    tokens: int
    boundaries: int
    rules: int
    requests: int
    audits: int
    results: int
    reservations: int


def configured_sqlite_service(
    database: Path,
    *,
    database_epoch: int | None = int(NOW.timestamp()),
) -> tuple[SQLiteV1Service, SerializedSQLiteConnection]:
    from vinctor_service.idempotency_keyring import load_idempotency_keyring

    key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=keyring)
    if database_epoch is not None:
        set_database_epoch(connection, database_epoch)
    return service, connection


def set_database_epoch(
    connection: SerializedSQLiteConnection,
    epoch: int,
) -> None:
    connection._connection.create_function(
        "strftime",
        2,
        lambda _format, _value: str(epoch),
    )


def seed_success_routes(
    service: SQLiteV1Service,
    *,
    now: datetime = NOW,
) -> None:
    service.insert_grant(
        Grant(
            grant_id="grnt_seed",
            grant_ref="grt_seed",
            workspace_id="ws_main",
            agent_id="agent_release",
            scopes=("write:repo/feature/*",),
            status="active",
            expires_at=now + timedelta(hours=1),
        )
    )
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        max_ttl_seconds=3_600,
        now=now,
    )
    request_specs = (
        ("grq_approve", "agent_release", ("write:repo/feature/readme",), "pending"),
        ("grq_reject", "agent_release", ("write:repo/feature/readme",), "pending"),
        ("grq_auto", "agent_release", ("write:repo/feature/readme",), "pending"),
        ("grq_approve_done", "agent_release", ("write:repo/feature/readme",), "approved"),
        ("grq_reject_done", "agent_release", ("write:repo/feature/readme",), "rejected"),
        ("grq_auto_done", "agent_release", ("write:repo/feature/readme",), "approved"),
        ("grq_approve_bad", "agent_release", ("bad scope",), "pending"),
        ("grq_approve_bounds", "agent_unbounded", ("write:repo/feature/readme",), "pending"),
        ("grq_auto_unmatched", "agent_unmatched", ("write:repo/feature/readme",), "pending"),
        (
            "grq_auto_bad",
            "agent_invalid_bounds",
            ("write:repo/feature/readme",),
            "pending",
        ),
        ("grq_auto_bounds", "agent_unbounded", ("write:repo/feature/readme",), "pending"),
    )
    for request_id, target_agent_id, scopes, status in request_specs:
        service.grant_request_repository.insert_request(
            GrantRequest(
                request_id=request_id,
                workspace_id="ws_main",
                requester_agent_id="agent_release",
                target_agent_id=target_agent_id,
                requested_scopes=scopes,
                requested_ttl_seconds=3600,
                reason="idempotency HTTP matrix",
                status=status,
                created_at=now,
            )
        )
    for index, target_agent_id in enumerate(
        ("agent_release", "agent_unbounded", "agent_invalid_bounds"),
        start=1,
    ):
        service.create_auto_approval_rule(
            AutoApprovalRule(
                rule_id=f"aar_seed_{index}",
                workspace_id="ws_main",
                name=f"matrix seed {index}",
                target_agent_id=target_agent_id,
                allowed_scopes=("write:repo/feature/*",),
                max_ttl_seconds=3_600,
                status="active",
                created_by="workspace:ws_main",
                created_at=now,
            )
        )


def seed_other_workspace(service: SQLiteV1Service) -> None:
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_other",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )


def _table_count(connection: SerializedSQLiteConnection, table: str) -> int:
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table,),
    ).fetchone()
    if exists is None:
        return 0
    row = connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()
    assert row is not None
    return int(row[0])


def _decided_request_count(connection: SerializedSQLiteConnection) -> int:
    row = connection.execute(
        "SELECT COUNT(*) FROM grant_requests WHERE status <> 'pending'"
    ).fetchone()
    assert row is not None
    return int(row[0])


def persisted_counts(connection: SerializedSQLiteConnection) -> PersistedCounts:
    return PersistedCounts(
        grants=_table_count(connection, "grants"),
        tokens=_table_count(connection, "subject_tokens"),
        boundaries=_table_count(connection, "boundaries"),
        rules=_table_count(connection, "auto_approval_rules"),
        requests=_decided_request_count(connection),
        audits=_table_count(connection, "audit_events"),
        results=_table_count(connection, "idempotency_results"),
        reservations=_table_count(connection, "idempotency_cipher_nonces"),
    )
