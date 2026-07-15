from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_service import (
    AutoApprovalRule,
    GrantRequestCreateRequest,
    SQLiteV1Service,
    WorkspaceIdentity,
)
from vinctor_service.grant_request_http import handle_v1_grant_requests_http
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
WORKSPACE_HEADERS = {"X-Workspace-Key": "workspace_key_main"}


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    return connect_sqlite(tmp_path / "vinctor.sqlite")


def workspace_identities() -> dict[str, WorkspaceIdentity]:
    return {"workspace_key_main": WorkspaceIdentity(workspace_id="ws_main")}


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


def approve(service: SQLiteV1Service, request_id: str):
    return handle_v1_grant_requests_http(
        method="POST",
        path=f"/v1/grant-requests/{request_id}/approve",
        headers=WORKSPACE_HEADERS,
        body=None,
        workspace_identities=workspace_identities(),
        service=service,
        now=NOW + timedelta(seconds=1),
    )


def auto_approve(service: SQLiteV1Service, request_id: str):
    return handle_v1_grant_requests_http(
        method="POST",
        path=f"/v1/grant-requests/{request_id}/auto-approve",
        headers=WORKSPACE_HEADERS,
        body=None,
        workspace_identities=workspace_identities(),
        service=service,
        now=NOW + timedelta(seconds=1),
    )


def test_approve_out_of_bounds_returns_403(tmp_path: Path) -> None:
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

    response = approve(service, "grq_main")

    assert response.status_code == 403
    assert response.body["reason"] == "scope_outside_issuable_bounds"
    conn.close()


def test_approve_ttl_exceeds_issuable_max_returns_403(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=900,
        now=NOW,
    )
    service.create_grant_request(create_request(ttl_seconds=3600), now=NOW)

    response = approve(service, "grq_main")

    assert response.status_code == 403
    assert response.body["reason"] == "ttl_exceeds_issuable_max"
    conn.close()


def test_approve_without_issuable_bounds_returns_403(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_grant_request(create_request(), now=NOW)

    response = approve(service, "grq_main")

    assert response.status_code == 403
    assert response.body["reason"] == "issuable_bounds_not_found"
    conn.close()


def test_auto_approve_out_of_bounds_returns_403(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_auto_approval_rule(
        AutoApprovalRule(
            rule_id="apr_deploy",
            workspace_id="ws_main",
            name="deploy auto approval",
            target_agent_id="agent_runner",
            allowed_scopes=("execute:deploy/*",),
            max_ttl_seconds=3600,
            status="active",
            created_by="workspace:ws_main",
            created_at=NOW,
        )
    )
    service.create_grant_request(
        create_request(scopes=("execute:deploy/production",)),
        now=NOW,
    )

    response = auto_approve(service, "grq_main")

    assert response.status_code == 403
    assert response.body["reason"] == "scope_outside_issuable_bounds"
    conn.close()


def test_approve_not_pending_still_returns_409(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_grant_request(create_request(), now=NOW)
    first = approve(service, "grq_main")
    assert first.status_code == 200

    second = approve(service, "grq_main")

    assert second.status_code == 409
    assert second.body["reason"] == "grant_request_not_pending"
    conn.close()


def test_approve_not_found_still_returns_404(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)

    response = approve(service, "grq_missing")

    assert response.status_code == 404
    assert response.body["reason"] == "grant_request_not_found"
    conn.close()
