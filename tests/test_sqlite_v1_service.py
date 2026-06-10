from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_core import BoundaryRegistrationInput, Grant, register_boundary
from vinctor_service import SQLiteV1Service, V1EnforceRequest

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


def test_sqlite_v1_service_preserves_unknown_grant_no_audit(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())

    response = service.enforce(
        request(grant_ref="grt_missing", action="push", resource="repo"),
        now=NOW,
    )

    assert response.status_code == 404
    assert response.error == "grant_not_found"
    assert response.decision is None
    assert audit_count(conn) == 0
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
