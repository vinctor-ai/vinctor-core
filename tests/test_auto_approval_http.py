from __future__ import annotations

from datetime import UTC, datetime

from vinctor_service import (
    InMemoryV1Service,
    WorkspaceIdentity,
    handle_v1_auto_approval_rules_http,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def workspace_identities() -> dict[str, WorkspaceIdentity]:
    return {"workspace_key_main": WorkspaceIdentity(workspace_id="ws_main")}


def create_body(
    *,
    allowed_scopes: list[str] | None = None,
) -> dict[str, object]:
    return {
        "name": "CI auto approval",
        "target_agent_id": "agent_runner",
        "allowed_scopes": allowed_scopes or ["execute:ci/*"],
        "max_ttl_seconds": 3600,
    }


def test_auto_approval_rule_http_create_list_and_disable() -> None:
    service = InMemoryV1Service()

    created = handle_v1_auto_approval_rules_http(
        method="POST",
        path="/v1/auto-approval-rules",
        headers={"X-Workspace-Key": "workspace_key_main"},
        body=create_body(),
        workspace_identities=workspace_identities(),
        service=service,
        now=NOW,
    )
    rule_id = created.body["rule_id"]
    listed = handle_v1_auto_approval_rules_http(
        method="GET",
        path="/v1/auto-approval-rules",
        headers={"X-Workspace-Key": "workspace_key_main"},
        body=None,
        workspace_identities=workspace_identities(),
        service=service,
        now=NOW,
    )
    disabled = handle_v1_auto_approval_rules_http(
        method="POST",
        path=f"/v1/auto-approval-rules/{rule_id}/disable",
        headers={"X-Workspace-Key": "workspace_key_main"},
        body=None,
        workspace_identities=workspace_identities(),
        service=service,
        now=NOW,
    )

    assert created.status_code == 201
    assert str(rule_id).startswith("apr_")
    assert created.body["workspace_id"] == "ws_main"
    assert created.body["status"] == "active"
    assert created.body["created_by"] == "workspace:ws_main"
    assert listed.status_code == 200
    assert listed.body["auto_approval_rules"] == [created.body]
    assert disabled.status_code == 200
    assert disabled.body["status"] == "disabled"
    assert disabled.body["updated_by"] == "workspace:ws_main"


def test_auto_approval_rule_http_requires_workspace_key() -> None:
    response = handle_v1_auto_approval_rules_http(
        method="POST",
        path="/v1/auto-approval-rules",
        headers={"X-Agent-Key": "agent_key_main"},
        body=create_body(),
        workspace_identities=workspace_identities(),
        service=InMemoryV1Service(),
        now=NOW,
    )

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"


def test_auto_approval_rule_http_rejects_invalid_scope() -> None:
    response = handle_v1_auto_approval_rules_http(
        method="POST",
        path="/v1/auto-approval-rules",
        headers={"X-Workspace-Key": "workspace_key_main"},
        body=create_body(allowed_scopes=["execute:ci"]),
        workspace_identities=workspace_identities(),
        service=InMemoryV1Service(),
        now=NOW,
    )

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert "invalid allowed scope" in response.body["reason"]


def test_auto_approval_rule_http_returns_404_for_missing_disable_target() -> None:
    response = handle_v1_auto_approval_rules_http(
        method="POST",
        path="/v1/auto-approval-rules/apr_missing/disable",
        headers={"X-Workspace-Key": "workspace_key_main"},
        body=None,
        workspace_identities=workspace_identities(),
        service=InMemoryV1Service(),
        now=NOW,
    )

    assert response.status_code == 404
    assert response.body["error"] == "auto_approval_rule_not_found"
