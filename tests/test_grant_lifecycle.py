from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_service import GrantIssueRequest, SQLiteV1Service, V1EnforceRequest
from vinctor_service.grants import DEFAULT_TTL_SECONDS

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


def audit_event_decisions(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return conn.execute(
        """
        SELECT event_type, decision
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
    assert audit_event_decisions(conn)[:2] == [
        ("grant_issued", "permit"),
        ("grant_revoked", "deny"),
    ]
    conn.close()


def test_missing_ttl_defaults_to_short_ttl(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    issued = service.issue_grant(
        GrantIssueRequest(
            workspace_id="ws_main",
            target_agent_id="agent_runner",
            requested_scopes=("execute:ci/test",),
            grant_id="grnt_issued",
            grant_ref="grt_issued",
        ),
        now=NOW,
    )

    assert issued.status == "issued"
    assert issued.grant is not None
    assert issued.grant.expires_at == NOW + timedelta(seconds=DEFAULT_TTL_SECONDS)

    # The grant_issued audit event references the grant whose persisted expiry
    # reflects the applied (defaulted) TTL, not the omitted requested TTL.
    assert audit_rows(conn)[0][0] == "grant_issued"
    persisted = service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main")
    assert persisted is not None
    assert persisted.expires_at == NOW + timedelta(seconds=DEFAULT_TTL_SECONDS)
    conn.close()


def test_ttl_within_agent_max_ttl_is_issued(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=3600,
        now=NOW,
    )

    issued = service.issue_grant(issue_request(ttl_seconds=1800), now=NOW)

    assert issued.status == "issued"
    assert issued.grant is not None
    assert issued.grant.expires_at == NOW + timedelta(seconds=1800)
    conn.close()


def test_ttl_exceeding_agent_max_ttl_is_rejected(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=1800,
        now=NOW,
    )

    result = service.issue_grant(issue_request(ttl_seconds=3600), now=NOW)

    assert result.status == "rejected"
    assert result.reason == "ttl_exceeds_issuable_max"
    assert service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main") is None
    assert audit_rows(conn) == []
    conn.close()


def test_ttl_at_agent_max_ttl_boundary_is_issued(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=1800,
        now=NOW,
    )

    result = service.issue_grant(issue_request(ttl_seconds=1800), now=NOW)

    assert result.status == "issued"
    conn.close()


def test_max_ttl_persists_and_is_shown_in_bounds(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=1800,
        now=NOW,
    )

    assert (
        service.scope_bounds_repository.get_max_ttl_seconds(
            workspace_id="ws_main",
            agent_id="agent_runner",
        )
        == 1800
    )
    conn.close()


def test_no_max_ttl_bound_allows_ttl_up_to_ceiling(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    issued = service.issue_grant(issue_request(ttl_seconds=7200), now=NOW)

    assert issued.status == "issued"
    assert (
        service.scope_bounds_repository.get_max_ttl_seconds(
            workspace_id="ws_main",
            agent_id="agent_runner",
        )
        is None
    )
    conn.close()


def test_ttl_exceeding_hard_ceiling_is_rejected(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    result = service.issue_grant(issue_request(ttl_seconds=10**9), now=NOW)

    assert result.status == "rejected"
    assert result.reason == "ttl_exceeds_max"
    assert audit_rows(conn) == []
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
