from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_service import GrantIssueRequest, SQLiteV1Service, V1EnforceRequest

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(tmp_path / "vinctor.sqlite")


def issue_request(
    *,
    scopes: tuple[str, ...] = ("execute:ci/test",),
    ttl_seconds: int = 3600,
    grant_ref: str = "grt_issued",
) -> GrantIssueRequest:
    return GrantIssueRequest(
        workspace_id="ws_main",
        target_agent_id="agent_runner",
        requested_scopes=scopes,
        ttl_seconds=ttl_seconds,
        grant_id="grnt_issued",
        grant_ref=grant_ref,
    )


def enforce_request(
    *,
    grant_ref: str = "grt_issued",
    action: str = "execute",
    resource: str = "ci/test",
) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_runner",
        grant_ref=grant_ref,
        action=action,
        resource=resource,
    )


def audit_rows(conn: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    return conn.execute(
        """
        SELECT event_type, reason, grant_ref, action
        FROM audit_events
        ORDER BY rowid
        """
    ).fetchall()


def test_workspace_can_issue_lookup_and_enforce_service_issued_grant(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test", "execute:ci/build", "read:secret/env"),
        now=NOW,
    )

    issued = service.issue_grant(issue_request(), now=NOW)

    assert issued.status == "issued"
    assert issued.grant is not None
    assert issued.grant.grant_ref == "grt_issued"
    assert issued.grant.expires_at == NOW + timedelta(seconds=3600)
    assert service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main") == issued.grant

    enforced = service.enforce(enforce_request(), now=NOW)

    assert enforced.status_code == 200
    assert enforced.decision == "permit"
    assert audit_rows(conn)[0] == (
        "grant_issued",
        "grant_issued",
        "grt_issued",
        "issue_grant",
    )
    conn.close()


def test_scopes_outside_agent_issuable_bounds_are_rejected(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    result = service.issue_grant(
        issue_request(scopes=("execute:deploy/production",)),
        now=NOW,
    )

    assert result.status == "rejected"
    assert result.reason == "scope_outside_issuable_bounds"
    assert service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main") is None
    assert audit_rows(conn) == []
    conn.close()


def test_ttl_expiration_is_enforced_for_issued_grants(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.issue_grant(issue_request(ttl_seconds=1), now=NOW)

    response = service.enforce(enforce_request(), now=NOW + timedelta(seconds=2))

    assert response.status_code == 403
    assert response.error == "grant_expired"
    conn.close()


def test_revoke_marks_grant_revoked_and_writes_audit(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.issue_grant(issue_request(), now=NOW)

    revoked = service.revoke_grant(
        grant_ref="grt_issued",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
    )

    assert revoked is not None
    grant, audit_event_id = revoked
    assert grant.status == "revoked"
    assert audit_event_id is not None
    denied = service.enforce(enforce_request(), now=NOW + timedelta(seconds=2))
    assert denied.status_code == 403
    assert denied.error == "grant_revoked"
    assert audit_rows(conn)[:2] == [
        ("grant_issued", "grant_issued", "grt_issued", "issue_grant"),
        ("grant_revoked", "grant_revoked", "grt_issued", "revoke_grant"),
    ]
    conn.close()


def test_lifecycle_audit_event_json_excludes_raw_inputs(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    service.issue_grant(issue_request(), now=NOW)

    row = conn.execute("SELECT event_json FROM audit_events").fetchone()
    event_json = json.loads(row[0])
    assert event_json["event_type"] == "grant_issued"
    assert event_json.keys().isdisjoint({"raw_tool_input", "raw_command", "prompt"})
    conn.close()
