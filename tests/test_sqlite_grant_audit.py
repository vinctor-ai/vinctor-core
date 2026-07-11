from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_core import Grant
from vinctor_service import (
    SQLiteAuditWriter,
    SQLiteGrantRepository,
    V1EnforceRequest,
    enforce_v1_contract,
    init_sqlite_schema,
    insert_grant,
)
from vinctor_service.sqlite import _grant_from_row

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


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
) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref=grant_ref,
        action=action,
        resource=resource,
    )


def connect_db(tmp_path: Path, name: str = "vinctor.sqlite") -> sqlite3.Connection:
    conn = sqlite3.connect(tmp_path / name)
    init_sqlite_schema(conn)
    return conn


def audit_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    return row[0]


def audit_row(conn: sqlite3.Connection, event_id: str) -> sqlite3.Row:
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM audit_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    assert row is not None
    return row


def test_sqlite_grant_ref_lookup_succeeds(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    inserted = grant()
    insert_grant(conn, inserted)

    loaded = SQLiteGrantRepository(conn).get_by_ref("grt_main")

    assert loaded == inserted
    conn.close()


def test_sqlite_insert_grant_rejects_duplicate_grant_ref(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    insert_grant(conn, grant())

    try:
        insert_grant(conn, grant(grant_id="grnt_other"))
    except ValueError as error:
        assert "duplicate grant_ref" in str(error)
    else:
        raise AssertionError("expected duplicate grant_ref to be rejected")
    finally:
        conn.close()


def test_sqlite_unknown_grant_returns_v1_403_without_audit(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    insert_grant(conn, grant())

    response = enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=SQLiteGrantRepository(conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(conn),
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit_count(conn) == 0
    conn.close()


def test_sqlite_permit_writes_audit_before_response(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    insert_grant(conn, grant())

    response = enforce_v1_contract(
        request(),
        grant_repository=SQLiteGrantRepository(conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(conn),
    )

    assert response.status_code == 200
    assert response.decision == "permit"

    row = audit_row(conn, response.audit_event_id or "")
    assert row["decision"] == "permit"
    assert row["reason"] == "permitted"
    assert row["workspace_id"] == "ws_main"
    assert row["agent_id"] == "agent_release"
    assert row["grant_id"] == "grnt_main"
    assert row["grant_ref"] == "grt_main"
    assert row["action"] == "write"
    assert row["resource"] == "repo/feature/readme"
    assert row["scope_attempted"] == "write:repo/feature/readme"
    assert row["scope_matched"] == "write:repo/feature/*"
    conn.close()


def test_sqlite_deny_writes_audit_before_response(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    insert_grant(conn, grant())

    response = enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=SQLiteGrantRepository(conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(conn),
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "action_denied"

    row = audit_row(conn, response.audit_event_id or "")
    assert row["decision"] == "deny"
    assert row["reason"] == "action_denied"
    assert row["action"] == "send"
    assert row["resource"] == "email/external"
    assert row["scope_attempted"] == "send:email/external"
    assert row["scope_matched"] is None
    conn.close()


def test_sqlite_audit_write_failure_fails_closed(tmp_path: Path) -> None:
    grant_conn = connect_db(tmp_path)
    insert_grant(grant_conn, grant())
    closed_audit_conn = connect_db(tmp_path, "closed.sqlite")
    closed_audit_conn.close()

    response = enforce_v1_contract(
        request(),
        grant_repository=SQLiteGrantRepository(grant_conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(closed_audit_conn),
    )

    assert response.status_code == 503
    assert response.error == "service_unavailable"
    assert response.decision is None
    assert response.audit_event_id is None
    grant_conn.close()


def test_sqlite_audit_schema_does_not_store_raw_tool_or_prompt_fields(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    insert_grant(conn, grant())
    response = enforce_v1_contract(
        request(),
        grant_repository=SQLiteGrantRepository(conn),
        now=NOW,
        audit_writer=SQLiteAuditWriter(conn),
    )

    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
    }
    forbidden = {"raw_tool_input", "raw_command", "prompt", "model_facing_reason"}
    assert columns.isdisjoint(forbidden)

    row = audit_row(conn, response.audit_event_id or "")
    event_data = json.loads(row["event_json"])
    assert event_data.keys().isdisjoint(forbidden)
    conn.close()


def test_grant_from_row_coerces_naive_expires_at_to_utc() -> None:
    # Defense-in-depth: a tz-naive expires_at in storage must be coerced to UTC so
    # the enforce comparison (now is always tz-aware) cannot TypeError.
    row = (
        "grnt_main",
        "grt_main",
        "ws_main",
        "agent_release",
        json.dumps(["write:repo/feature/*"]),
        "active",
        "2026-06-10T13:00:00",  # naive (no tzinfo)
    )

    loaded = _grant_from_row(row)

    assert loaded.expires_at is not None
    assert loaded.expires_at.tzinfo is UTC


def test_grant_from_row_preserves_aware_expires_at() -> None:
    row = (
        "grnt_main",
        "grt_main",
        "ws_main",
        "agent_release",
        json.dumps(["write:repo/feature/*"]),
        "active",
        "2026-06-10T13:00:00+00:00",
    )

    loaded = _grant_from_row(row)

    assert loaded.expires_at == datetime(2026, 6, 10, 13, 0, tzinfo=UTC)
