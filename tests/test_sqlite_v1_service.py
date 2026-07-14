from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_core import BoundaryRegistrationInput, Grant, register_boundary
from vinctor_service import (
    SQLiteV1Service,
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
    V1ObserveRequest,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(tmp_path / "vinctor.sqlite")


def grant(
    *,
    grant_id: str = "grnt_main",
    grant_ref: str = "grt_main",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    scopes: tuple[str, ...] = ("write:repo/feature/*",),
    status: str = "active",
) -> Grant:
    return Grant(
        grant_id=grant_id,
        grant_ref=grant_ref,
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=scopes,
        status=status,
        expires_at=NOW + timedelta(hours=1),
    )


def request(
    *,
    grant_ref: str = "grt_main",
    action: str = "write",
    resource: str = "repo/feature/readme",
    boundary_id: str | None = None,
) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref=grant_ref,
        action=action,
        resource=resource,
        boundary_id=boundary_id,
    )


def audit_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    return row[0]


def test_sqlite_v1_service_initializes_schema_and_inserts_grant(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)

    service.insert_grant(grant())

    loaded = service.grant_repository.get_by_ref("grt_main")
    assert loaded == grant()
    conn.close()


def test_sqlite_v1_service_permits_and_records_audit(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())

    response = service.enforce(request(), now=NOW)

    assert response.status_code == 200
    assert response.decision == "permit"
    assert audit_count(conn) == 1
    row = conn.execute(
        "SELECT decision, reason, scope_matched FROM audit_events WHERE event_id = ?",
        (response.audit_event_id,),
    ).fetchone()
    assert row == ("permit", "permitted", "write:repo/feature/*")
    conn.close()


def test_sqlite_v1_service_records_mapped_observation(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)

    response = service.observe(
        V1ObserveRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            classification="mapped",
            action="read",
            resource="repo/feature/readme",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    row = conn.execute(
        "SELECT event_type, decision, grant_ref, scope_attempted "
        "FROM audit_events WHERE event_id = ?",
        (response.audit_event_id,),
    ).fetchone()
    assert row == ("action_observed", "permit", "", "read:repo/feature/readme")
    conn.close()


def test_sqlite_v1_service_exposes_audit_events(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())

    permit = service.enforce(request(), now=NOW)
    deny = service.enforce(
        request(action="send", resource="email/external"),
        now=NOW,
    )

    assert [event.event_id for event in service.audit_events] == [
        permit.audit_event_id,
        deny.audit_event_id,
    ]
    assert service.get_audit_event(permit.audit_event_id or "") == service.audit_events[0]
    assert service.get_audit_event("evt_missing") is None
    conn.close()


def test_sqlite_v1_service_unknown_grant_records_rejection(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())

    response = service.enforce(
        request(grant_ref="grt_missing", action="push", resource="repo"),
        now=NOW,
    )

    # Timing oracle closed: unknown grant records the same one rejection row a
    # foreign grant does.
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit_count(conn) == 1
    conn.close()


def test_sqlite_v1_service_records_deny_after_permit_in_order(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())

    permit = service.enforce(request(), now=NOW)
    deny = service.enforce(
        request(action="send", resource="email/external"),
        now=NOW,
    )

    rows = conn.execute(
        "SELECT event_id, decision, reason FROM audit_events ORDER BY rowid"
    ).fetchall()
    assert rows == [
        (permit.audit_event_id, "permit", "permitted"),
        (deny.audit_event_id, "deny", "action_denied"),
    ]
    conn.close()


def test_sqlite_v1_service_uses_boundary_registry(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())
    boundary = register_boundary(
        service.boundary_registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_main",
    )

    response = service.enforce(request(boundary_id=boundary.boundary_id), now=NOW)

    assert response.status_code == 200
    row = conn.execute(
        "SELECT boundary_id, runtime, boundary_type FROM audit_events WHERE event_id = ?",
        (response.audit_event_id,),
    ).fetchone()
    assert row == ("bnd_main", "claude-code", "pretooluse")
    conn.close()


def test_sqlite_v1_service_fails_closed_for_disabled_boundary(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())
    service.register_boundary(
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_main",
    )
    service.disable_boundary(
        boundary_id="bnd_main",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
    )

    response = service.enforce(request(boundary_id="bnd_main"), now=NOW)

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "boundary_inactive"
    assert audit_count(conn) == 1
    conn.close()


def test_sqlite_v1_service_manages_boundaries(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)

    boundary = service.register_boundary(
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_main",
    )

    assert service.list_boundaries("ws_main") == (boundary,)
    assert service.get_boundary(boundary_id="bnd_main", workspace_id="ws_main") == boundary
    assert service.get_boundary(boundary_id="bnd_main", workspace_id="ws_other") is None
    disabled = service.disable_boundary(
        boundary_id="bnd_main",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
    )
    assert disabled is not None
    assert disabled.status == "disabled"

    enabled = service.enable_boundary(
        boundary_id="bnd_main",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=2),
    )
    assert enabled is not None
    assert enabled.status == "active"
    assert service.list_boundaries("ws_main") == (enabled,)
    assert service.list_boundaries("ws_other") == ()
    conn.close()


def test_sqlite_v1_service_delegated_enforce_persists_enforcing_principal(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())

    response = service.delegated_enforce(
        V1DelegatedEnforceRequest(
            pep_id="pep_git_host",
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
            pep_workspace_id="ws_main",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    # The PEP principal round-trips through JSON-persisted audit storage.
    persisted = service.get_audit_event(response.audit_event_id or "")
    assert persisted is not None
    assert persisted.agent_id == "agent_release"
    assert persisted.enforcing_principal == "pep_git_host"
    conn.close()


def test_sqlite_v1_service_delegated_enforce_persists_proven_identity(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())

    minted = service.mint_subject_token(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        ttl_seconds=300,
        now=NOW,
    )
    assert minted.status == "minted"

    response = service.delegated_enforce(
        V1DelegatedEnforceRequest(
            pep_id="pep_git_host",
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
            pep_workspace_id="ws_main",
            subject_token=minted.token,
        ),
        now=NOW,
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    # The proven-identity flags round-trip through JSON-persisted audit storage.
    persisted = service.get_audit_event(response.audit_event_id or "")
    assert persisted is not None
    assert persisted.identity_proven is True
    assert persisted.token_id == minted.token_id
    conn.close()


def test_sqlite_audit_writer_round_trips_identity_proven_and_token_id(
    tmp_path: Path,
) -> None:
    from vinctor_core.models import AuditEvent
    from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema

    conn = connect_db(tmp_path)
    init_sqlite_schema(conn)
    writer = SQLiteAuditWriter(conn)
    event = AuditEvent(
        event_id="evt_proven",
        event_type="action_permitted",
        decision="permit",
        reason="scope_matched",
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_id="grnt_main",
        grant_ref="grt_main",
        action="write",
        resource="repo/feature/readme",
        scope_attempted="write:repo/feature/readme",
        scope_matched="write:repo/feature/*",
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=NOW,
        identity_proven=True,
        token_id="vtk_x",
    )
    writer.write(event)

    persisted = writer.get("evt_proven")
    assert persisted is not None
    assert persisted.identity_proven is True
    assert persisted.token_id == "vtk_x"
    conn.close()


def test_sqlite_audit_writer_round_trips_rejection_fields(tmp_path: Path) -> None:
    from vinctor_core.audit import (
        EVENT_AUTH_FAILED,
        REASON_AUTH_FAILED,
        build_rejection_audit_event,
    )
    from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema

    conn = connect_db(tmp_path)
    init_sqlite_schema(conn)
    writer = SQLiteAuditWriter(conn)
    event = build_rejection_audit_event(
        reason_code=REASON_AUTH_FAILED,
        workspace_id="ws_main",
        agent_id="",
        created_at=NOW + timedelta(seconds=30),
        event_type=EVENT_AUTH_FAILED,
        action="/v1/enforce",
        scope_attempted="",
        event_id="evt_rejected",
        occurrence_count=3,
        first_seen_at=NOW,
        last_seen_at=NOW + timedelta(seconds=30),
    )
    writer.write(event)

    persisted = writer.get("evt_rejected")
    assert persisted is not None
    assert persisted.reason_code == REASON_AUTH_FAILED
    assert persisted.occurrence_count == 3
    assert persisted.first_seen_at == NOW
    assert persisted.last_seen_at == NOW + timedelta(seconds=30)
    conn.close()


def test_sqlite_v1_service_delegated_enforce_blocks_cross_workspace(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant(workspace_id="ws_other"))

    response = service.delegated_enforce(
        V1DelegatedEnforceRequest(
            pep_id="pep_git_host",
            workspace_id="ws_other",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
            pep_workspace_id="ws_main",
        ),
        now=NOW,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    # ADR 0008: the cross-workspace PEP attempt is recorded for the operator.
    assert audit_count(conn) == 1
    conn.close()


def test_sqlite_v1_service_can_use_existing_initialized_schema(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    first = SQLiteV1Service(conn)
    first.insert_grant(grant())

    second = SQLiteV1Service(conn, initialize_schema=False)
    response = second.enforce(request(), now=NOW)

    assert response.status_code == 200
    assert audit_count(conn) == 1
    conn.close()
