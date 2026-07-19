from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_core import (
    Boundary,
    BoundaryRegistrationInput,
    Grant,
    disable_boundary,
    enable_boundary,
    register_boundary,
)
from vinctor_service import (
    SQLiteAuditWriter,
    SQLiteBoundaryRegistry,
    SQLiteGrantRepository,
    V1EnforceRequest,
    enforce_v1_contract,
    init_sqlite_schema,
    insert_grant,
)
from vinctor_service.control_audit import ControlPlaneAuditor
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    conn = connect_sqlite(tmp_path / "vinctor.sqlite")
    init_sqlite_schema(conn)
    return conn


def boundary_registry(conn: sqlite3.Connection) -> SQLiteBoundaryRegistry:
    return SQLiteBoundaryRegistry(
        conn, ControlPlaneAuditor(SQLiteAuditWriter(conn))
    )


def grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def registration(
    *,
    workspace_id: str = "ws_main",
    name: str = "claude-code-local",
    status: str = "active",
) -> BoundaryRegistrationInput:
    return BoundaryRegistrationInput(
        workspace_id=workspace_id,
        name=name,
        runtime="claude-code",
        boundary_type="pretooluse",
        status=status,
    )


def request(*, boundary_id: str) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        action="write",
        resource="repo/feature/readme",
        boundary_id=boundary_id,
    )


def audit_row(conn: sqlite3.Connection, event_id: str) -> sqlite3.Row:
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM audit_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    assert row is not None
    return row


def test_sqlite_boundary_registry_registers_and_lists_boundaries(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)

    boundary = register_boundary(
        registry,
        registration(),
        now=NOW,
        boundary_id="bnd_main",
        enforcing_principal="workspace:ws_main",
    )

    assert registry.get("bnd_main") == boundary
    assert registry.list_for_workspace("ws_main") == [boundary]
    assert registry.list_for_workspace("ws_other") == []
    conn.close()


def test_sqlite_boundary_registry_rejects_duplicate_names_in_workspace(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)
    register_boundary(
        registry, registration(), now=NOW, boundary_id="bnd_one",
        enforcing_principal="workspace:ws_main",
    )

    try:
        register_boundary(
        registry, registration(), now=NOW, boundary_id="bnd_two",
        enforcing_principal="workspace:ws_main",
    )
    except ValueError as error:
        assert "boundary name must be unique" in str(error)
    else:
        raise AssertionError("expected duplicate boundary name to be rejected")
    finally:
        conn.close()


def test_sqlite_boundary_registry_allows_same_name_in_different_workspaces(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)

    first = register_boundary(
        registry,
        registration(workspace_id="ws_main"),
        now=NOW,
        boundary_id="bnd_main",
        enforcing_principal="workspace:ws_main",
    )
    second = register_boundary(
        registry,
        registration(workspace_id="ws_other"),
        now=NOW,
        boundary_id="bnd_other",
        enforcing_principal="workspace:ws_other",
    )

    assert registry.list_for_workspace("ws_main") == [first]
    assert registry.list_for_workspace("ws_other") == [second]
    conn.close()


def test_sqlite_boundary_registry_disable_and_enable_persist_status(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)
    register_boundary(
        registry, registration(), now=NOW, boundary_id="bnd_main",
        enforcing_principal="workspace:ws_main",
    )

    disabled = disable_boundary(
        registry,
        boundary_id="bnd_main",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
        enforcing_principal="workspace:ws_main",
    )
    assert disabled is not None
    assert disabled.status == "disabled"
    assert registry.get("bnd_main") == disabled

    enabled = enable_boundary(
        registry,
        boundary_id="bnd_main",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=2),
        enforcing_principal="workspace:ws_main",
    )
    assert enabled is not None
    assert enabled.status == "active"
    assert registry.get("bnd_main") == enabled
    conn.close()


def test_sqlite_durable_registry_fails_loud_without_attribution(
    tmp_path: Path,
) -> None:
    # A durable registry must NEVER write an unattributed control event
    # (PKA-56 B4). The core helpers always reach it through the add_audited
    # probe, so these paths only fire on misuse — and each must fail loudly and
    # write NOTHING, never a NULL-principal row on the tamper-evident chain.
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)

    def counts() -> tuple[int, int]:
        boundaries = conn.execute("SELECT COUNT(*) FROM boundaries").fetchone()[0]
        events = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
        return (boundaries, events)

    assert hasattr(registry, "add_audited")
    boundary = Boundary(
        boundary_id="bnd_x",
        workspace_id="ws_main",
        name="claude-code-local",
        runtime="claude-code",
        boundary_type="pretooluse",
        mode="fail_closed",
        status="active",
        created_at=NOW,
        updated_at=NOW,
    )
    before = counts()

    # Bare BoundaryRegistry.add() carries no principal: a durable registry
    # must raise rather than delegate to an unattributed audited write.
    try:
        registry.add(boundary)  # type: ignore[attr-defined]
    except NotImplementedError:
        pass
    else:
        raise AssertionError("expected durable bare add() to fail loudly")
    assert counts() == before

    # Omitted principal: the keyword is required.
    try:
        registry.add_audited(boundary, operation="register")  # type: ignore[call-arg]
    except TypeError:
        pass
    else:
        raise AssertionError("expected add_audited to require enforcing_principal")
    assert counts() == before

    # Empty principal: rejected before any mutation, not written as NULL/"".
    try:
        registry.add_audited(boundary, operation="register", enforcing_principal="")
    except ValueError:
        pass
    else:
        raise AssertionError("expected add_audited to reject an empty principal")
    assert counts() == before
    conn.close()


def test_sqlite_boundary_context_is_persisted_in_audit_event(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)
    insert_grant(conn, grant())
    register_boundary(
        registry, registration(), now=NOW, boundary_id="bnd_main",
        enforcing_principal="workspace:ws_main",
    )

    response = enforce_v1_contract(
        request(boundary_id="bnd_main"),
        grant_repository=SQLiteGrantRepository(conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(conn),
        boundary_registry=registry,
    )

    assert response.status_code == 200
    row = audit_row(conn, response.audit_event_id or "")
    assert row["boundary_id"] == "bnd_main"
    assert row["runtime"] == "claude-code"
    assert row["boundary_type"] == "pretooluse"
    event_data = json.loads(row["event_json"])
    assert event_data["boundary_id"] == "bnd_main"
    assert event_data["runtime"] == "claude-code"
    assert event_data["boundary_type"] == "pretooluse"
    conn.close()


def test_sqlite_disabled_boundary_fails_closed_and_writes_audit(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)
    insert_grant(conn, grant())
    register_boundary(
        registry, registration(), now=NOW, boundary_id="bnd_main",
        enforcing_principal="workspace:ws_main",
    )
    disable_boundary(
        registry,
        boundary_id="bnd_main",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
        enforcing_principal="workspace:ws_main",
    )

    response = enforce_v1_contract(
        request(boundary_id="bnd_main"),
        grant_repository=SQLiteGrantRepository(conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(conn),
        boundary_registry=registry,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "boundary_unavailable"  # coarse for the agent
    row = audit_row(conn, response.audit_event_id or "")
    assert row["decision"] == "deny"
    assert row["reason"] == "boundary_inactive"  # operator audit keeps precise
    assert row["boundary_id"] == "bnd_main"
    assert row["runtime"] == "claude-code"
    assert row["boundary_type"] == "pretooluse"
    conn.close()


def test_sqlite_missing_boundary_fails_closed_with_attempted_id_only(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    registry = boundary_registry(conn)
    insert_grant(conn, grant())

    response = enforce_v1_contract(
        request(boundary_id="bnd_missing"),
        grant_repository=SQLiteGrantRepository(conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(conn),
        boundary_registry=registry,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "boundary_unavailable"
    row = audit_row(conn, response.audit_event_id or "")
    assert row["reason"] == "boundary_not_found"  # operator audit keeps precise
    assert row["boundary_id"] == "bnd_missing"
    assert row["runtime"] is None
    assert row["boundary_type"] is None
    conn.close()
