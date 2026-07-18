from __future__ import annotations

from datetime import UTC, datetime

from vinctor_service import (
    InMemoryV1Service,
    WorkspaceIdentity,
    handle_v1_auto_approval_rules_http,
)


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    service = InMemoryV1Service()
    workspace_identities = {"workspace_key_demo": WorkspaceIdentity(workspace_id="ws_demo")}

    created = handle_v1_auto_approval_rules_http(
        method="POST",
        path="/v1/auto-approval-rules",
        headers={"X-Workspace-Key": "workspace_key_demo"},
        body={
            "name": "CI admin rule",
            "target_agent_id": "agent_runner",
            "allowed_scopes": ["execute:ci/jobs/*"],
            "max_ttl_seconds": 3600,
        },
        workspace_identities=workspace_identities,
        service=service,
        now=now,
    )
    assert created.status_code == 201

    agent_attempt = handle_v1_auto_approval_rules_http(
        method="POST",
        path="/v1/auto-approval-rules",
        headers={"X-Agent-Key": "agent_key_demo"},
        body={
            "name": "Agent self rule",
            "target_agent_id": "agent_runner",
            "allowed_scopes": ["execute:ci/jobs/*"],
            "max_ttl_seconds": 3600,
        },
        workspace_identities=workspace_identities,
        service=service,
        now=now,
    )
    assert agent_attempt.status_code == 401

    listed = handle_v1_auto_approval_rules_http(
        method="GET",
        path="/v1/auto-approval-rules",
        headers={"X-Workspace-Key": "workspace_key_demo"},
        body=None,
        workspace_identities=workspace_identities,
        service=service,
        now=now,
    )
    assert listed.status_code == 200
    assert listed.body["auto_approval_rules"] == [created.body]

    disabled = handle_v1_auto_approval_rules_http(
        method="POST",
        path=f"/v1/auto-approval-rules/{created.body['rule_id']}/disable",
        headers={"X-Workspace-Key": "workspace_key_demo"},
        body=None,
        workspace_identities=workspace_identities,
        service=service,
        now=now,
    )
    assert disabled.status_code == 200
    assert disabled.body["status"] == "disabled"

    print("ALL AUTO-APPROVAL HTTP ADMIN STEPS PASSED")


if __name__ == "__main__":
    main()
