from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_service import (
    GrantRequestCreateRequest,
    SQLiteV1Service,
    V1EnforceRequest,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(tmp_path / "vinctor.sqlite")


def create_request(
    *,
    scopes: tuple[str, ...] = ("execute:ci/test",),
    ttl_seconds: int = 3600,
    request_id: str = "grq_main",
) -> GrantRequestCreateRequest:
    return GrantRequestCreateRequest(
        workspace_id="ws_main",
        requester_agent_id="agent_runner",
        requested_scopes=scopes,
        requested_ttl_seconds=ttl_seconds,
        reason="run the CI validation task",
        request_id=request_id,
    )


def audit_events(conn: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in conn.execute(
            "SELECT event_type FROM audit_events ORDER BY rowid"
        ).fetchall()
    ]


def audit_event_decisions(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return conn.execute(
        """
        SELECT event_type, decision
        FROM audit_events
        ORDER BY rowid
        """
    ).fetchall()


def test_agent_can_create_pending_grant_request(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)

    created = service.create_grant_request(create_request(), now=NOW)

    assert created.status == "created"
    assert created.request is not None
    assert created.request.status == "pending"
    assert created.request.requester_agent_id == "agent_runner"
    assert created.request.target_agent_id == "agent_runner"
    assert service.lookup_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
    ) == created.request
    assert audit_events(conn) == ["grant_requested"]
    conn.close()


def test_workspace_approval_issues_grant_and_enforce_can_consume_it(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_grant_request(create_request(), now=NOW)

    approved = service.approve_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="CI task is expected",
        now=NOW + timedelta(seconds=1),
    )

    assert approved.status == "approved"
    assert approved.request is not None
    assert approved.grant is not None
    assert approved.request.status == "approved"
    assert approved.request.issued_grant_ref == approved.grant.grant_ref
    assert approved.grant.scopes == ("execute:ci/test",)

    enforced = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main",
            agent_id="agent_runner",
            grant_ref=approved.grant.grant_ref,
            action="execute",
            resource="ci/test",
        ),
        now=NOW + timedelta(seconds=2),
    )

    assert enforced.status_code == 200
    assert enforced.decision == "permit"
    assert audit_events(conn) == [
        "grant_requested",
        "grant_issued",
        "grant_request_approved",
        "action_permitted",
    ]
    conn.close()


def test_workspace_rejection_keeps_request_without_grant(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_grant_request(create_request(), now=NOW)

    rejected = service.reject_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="not needed for this task",
        now=NOW + timedelta(seconds=1),
    )

    assert rejected.status == "rejected"
    assert rejected.request is not None
    assert rejected.request.status == "rejected"
    assert rejected.request.issued_grant_ref is None
    assert service.list_grant_requests(workspace_id="ws_main") == (rejected.request,)
    assert audit_events(conn) == ["grant_requested", "grant_request_rejected"]
    assert audit_event_decisions(conn) == [
        ("grant_requested", "permit"),
        ("grant_request_rejected", "deny"),
    ]
    conn.close()


def test_approval_fails_when_requested_scope_is_outside_bounds(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_grant_request(
        create_request(scopes=("execute:deploy/production",)),
        now=NOW,
    )

    failed = service.approve_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="attempt approval",
        now=NOW + timedelta(seconds=1),
    )

    assert failed.status == "failed"
    assert failed.reason == "scope_outside_issuable_bounds"
    assert failed.grant is None
    assert service.lookup_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
    ).status == "pending"
    # ADR 0008: the approval's out-of-bounds issuance attempt is recorded.
    assert audit_events(conn) == ["grant_requested", "grant_issue_rejected"]
    conn.close()


def test_decided_grant_request_cannot_be_decided_again(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_grant_request(create_request(), now=NOW)
    service.reject_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason=None,
        now=NOW + timedelta(seconds=1),
    )

    second = service.reject_grant_request(
        request_id="grq_main",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason=None,
        now=NOW + timedelta(seconds=2),
    )

    assert second.status == "failed"
    assert second.reason == "grant_request_not_pending"
    conn.close()
