from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread
from typing import Any

import pytest

from vinctor_core import BoundaryRegistrationInput, Grant, register_boundary
from vinctor_core.models import AuditEvent
from vinctor_service import (
    AgentIdentity,
    GrantRequestCreateRequest,
    InMemoryV1Service,
    Metrics,
    PepIdentity,
    WorkspaceIdentity,
    create_v1_http_handler,
    create_v1_http_server,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


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


def service() -> InMemoryV1Service:
    return InMemoryV1Service(grants=(grant(),))


def identities() -> dict[str, AgentIdentity]:
    return {
        "agent_key_main": AgentIdentity(
            workspace_id="ws_main",
            agent_id="agent_release",
        )
    }


def workspace_identities() -> dict[str, WorkspaceIdentity]:
    return {
        "workspace_key_main": WorkspaceIdentity(workspace_id="ws_main"),
    }


def body(
    *,
    grant_ref: str = "grt_main",
    action: str = "write",
    resource: str = "repo/feature/readme",
) -> dict[str, str]:
    return {"grant_ref": grant_ref, "action": action, "resource": resource}


def pep_identities() -> dict[str, PepIdentity]:
    return {
        "pep_key_main": PepIdentity(workspace_id="ws_main", pep_id="pep_git_host"),
    }


@contextmanager
def running_server(
    service_instance: InMemoryV1Service,
    *,
    workspace_keys: dict[str, WorkspaceIdentity] | None = None,
    pep_keys: dict[str, PepIdentity] | None = None,
    metrics: Metrics | None = None,
) -> Iterator[ThreadingHTTPServer]:
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service_instance,
        agent_identities=identities(),
        workspace_identities=workspace_keys,
        pep_identities=pep_keys,
        clock=lambda: NOW,
        metrics=metrics,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def post_json(
    server: ThreadingHTTPServer,
    *,
    payload: object = None,
    headers: dict[str, str] | None = None,
    path: str = "/v1/enforce",
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    request_headers = {
        "Content-Type": "application/json",
        **({"X-Agent-Key": "agent_key_main"} if headers is None else headers),
    }
    conn.request(
        "POST",
        path,
        body=json.dumps(body() if payload is None else payload),
        headers=request_headers,
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


def raw_request(
    server: ThreadingHTTPServer,
    *,
    method: str,
    request_body: str = "",
    headers: dict[str, str] | None = None,
    path: str = "/v1/enforce",
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    conn.request(
        method,
        path,
        body=request_body,
        headers=headers or {"X-Agent-Key": "agent_key_main"},
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


def test_local_http_service_permits_v1_enforce_request() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server)

    assert status == 200
    assert response["decision"] == "permit"
    assert response["grant_id"] == "grnt_main"
    assert response["agent_id"] == "agent_release"
    assert response["scope_matched"] == "write:repo/feature/*"
    assert len(svc.audit_events) == 1


def test_local_http_service_denies_and_records_audit() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(
            server,
            payload=body(action="send", resource="email/external"),
        )

    assert status == 403
    assert response["decision"] == "deny"
    assert response["error"] == "action_denied"
    assert len(svc.audit_events) == 1
    assert svc.audit_events[0].decision == "deny"


def test_local_http_service_keeps_v1_body_strict() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(
            server,
            payload={**body(), "boundary_id": "bnd_body"},
        )

    assert status == 400
    assert response["error"] == "invalid_request"
    assert svc.audit_events == ()


def delegated_body(
    *,
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    grant_ref: str = "grt_main",
    action: str = "write",
    resource: str = "repo/feature/readme",
) -> dict[str, str]:
    return {
        "workspace_id": workspace_id,
        "agent_id": agent_id,
        "grant_ref": grant_ref,
        "action": action,
        "resource": resource,
    }


def test_local_http_delegated_enforce_permits_via_pep_key() -> None:
    svc = service()

    with running_server(svc, pep_keys=pep_identities()) as server:
        status, response = post_json(
            server,
            payload=delegated_body(),
            headers={"X-PEP-Key": "pep_key_main"},
            path="/v1/enforce/delegated",
        )

    assert status == 200
    assert response["decision"] == "permit"
    assert svc.audit_events[0].enforcing_principal == "pep_git_host"


def test_local_http_delegated_enforce_rejects_agent_key() -> None:
    svc = service()

    # An agent key on the delegated path does not resolve to a PEP identity.
    with running_server(svc, pep_keys=pep_identities()) as server:
        status, response = post_json(
            server,
            payload=delegated_body(),
            headers={"X-Agent-Key": "agent_key_main"},
            path="/v1/enforce/delegated",
        )

    assert status == 401
    assert response["error"] == "authentication_required"
    # ADR 0008: the authentication failure is recorded (rate-limited) for the operator.
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_local_http_plain_enforce_rejects_pep_key() -> None:
    svc = service()

    # A PEP key cannot drive the agent-authenticated /v1/enforce path.
    with running_server(svc, pep_keys=pep_identities()) as server:
        status, response = post_json(
            server,
            payload=body(),
            headers={"X-PEP-Key": "pep_key_main"},
            path="/v1/enforce",
        )

    assert status == 401
    assert response["error"] == "authentication_required"
    # ADR 0008: the authentication failure is recorded (rate-limited) for the operator.
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_local_http_service_rejects_invalid_json() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = raw_request(
            server,
            method="POST",
            request_body="{not-json",
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert status == 400
    assert response["error"] == "invalid_json"
    assert svc.audit_events == ()


def test_local_http_service_requires_agent_key() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server, headers={})

    assert status == 401
    assert response["error"] == "authentication_required"
    # ADR 0008: the authentication failure is recorded (rate-limited) for the operator.
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_local_http_service_maps_boundary_header() -> None:
    svc = service()
    boundary = register_boundary(
        svc.boundary_registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_http",
    )

    with running_server(svc) as server:
        status, response = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Vinctor-Boundary-Id": boundary.boundary_id,
            },
        )

    assert status == 200
    assert response["decision"] == "permit"
    assert svc.audit_events[0].boundary_id == "bnd_http"
    assert svc.audit_events[0].runtime == "claude-code"
    assert svc.audit_events[0].boundary_type == "pretooluse"


def test_local_http_service_returns_404_for_unknown_route() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server, path="/v1/unknown")

    assert status == 404
    assert response["error"] == "not_found"
    assert svc.audit_events == ()


def test_local_http_service_requires_post_for_enforce() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = raw_request(server, method="GET")

    assert status == 405
    assert response["error"] == "method_not_allowed"
    assert svc.audit_events == ()


def test_local_http_service_creates_boundary_then_enforces_with_it() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        create_status, created = post_json(
            server,
            path="/v1/boundaries",
            headers={"X-Workspace-Key": "workspace_key_main"},
            payload={
                "name": "claude-code-local",
                "runtime": "claude-code",
                "boundary_type": "pretooluse",
                "mode": "fail_closed",
            },
        )
        list_status, listed = raw_request(
            server,
            method="GET",
            path="/v1/boundaries",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        get_status, loaded = raw_request(
            server,
            method="GET",
            path=f"/v1/boundaries/{created['boundary_id']}",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        disable_status, disabled = raw_request(
            server,
            method="POST",
            path=f"/v1/boundaries/{created['boundary_id']}/disable",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        disabled_enforce_status, disabled_enforce = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Vinctor-Boundary-Id": created["boundary_id"],
            },
        )
        enable_status, enabled = raw_request(
            server,
            method="POST",
            path=f"/v1/boundaries/{created['boundary_id']}/enable",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        enforce_status, enforced = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Vinctor-Boundary-Id": created["boundary_id"],
            },
        )

    assert create_status == 201
    assert created["boundary_id"].startswith("bnd_")
    assert list_status == 200
    assert listed == {"boundaries": [created]}
    assert get_status == 200
    assert loaded == created
    assert disable_status == 200
    assert disabled["status"] == "disabled"
    assert disabled_enforce_status == 403
    assert disabled_enforce["error"] == "boundary_inactive"
    assert enable_status == 200
    assert enabled["status"] == "active"
    assert enforce_status == 200
    assert enforced["decision"] == "permit"
    assert [event.decision for event in svc.audit_events] == ["deny", "permit"]
    assert [event.boundary_id for event in svc.audit_events] == [
        created["boundary_id"],
        created["boundary_id"],
    ]
    assert [event.runtime for event in svc.audit_events] == ["claude-code", "claude-code"]
    assert [event.boundary_type for event in svc.audit_events] == [
        "pretooluse",
        "pretooluse",
    ]


def test_local_http_workspace_can_issue_lookup_revoke_and_enforce_grant() -> None:
    svc = InMemoryV1Service()
    svc.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        issue_status, issued = post_json(
            server,
            path="/v1/grants",
            headers={"X-Workspace-Key": "workspace_key_main"},
            payload={
                "agent_id": "agent_release",
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
            },
        )
        lookup_status, looked_up = raw_request(
            server,
            method="GET",
            path=f"/v1/grants/{issued['grant_ref']}",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        enforce_status, enforced = post_json(
            server,
            payload=body(grant_ref=issued["grant_ref"]),
            headers={"X-Agent-Key": "agent_key_main"},
        )
        revoke_status, revoked = raw_request(
            server,
            method="POST",
            path=f"/v1/grants/{issued['grant_ref']}/revoke",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        revoked_enforce_status, revoked_enforce = post_json(
            server,
            payload=body(grant_ref=issued["grant_ref"]),
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert issue_status == 201
    assert issued["grant_ref"].startswith("grt_")
    assert issued["agent_id"] == "agent_release"
    assert issued["scopes"] == ["write:repo/feature/readme"]
    assert lookup_status == 200
    assert looked_up["grant_ref"] == issued["grant_ref"]
    assert enforce_status == 200
    assert enforced["decision"] == "permit"
    assert revoke_status == 200
    assert revoked["status"] == "revoked"
    assert revoked_enforce_status == 403
    assert revoked_enforce["error"] == "grant_revoked"
    assert [event.event_type for event in svc.audit_events][:2] == [
        "grant_issued",
        "action_permitted",
    ]
    assert svc.audit_events[2].event_type == "grant_revoked"


def test_local_http_workspace_lists_grants_with_filters() -> None:
    svc = InMemoryV1Service(
        grants=(
            grant(),
            Grant(
                grant_id="grnt_other_agent",
                grant_ref="grt_other_agent",
                workspace_id="ws_main",
                agent_id="agent_other",
                scopes=("send:email/external",),
                status="active",
                expires_at=NOW + timedelta(hours=1),
            ),
            Grant(
                grant_id="grnt_revoked",
                grant_ref="grt_revoked",
                workspace_id="ws_main",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="revoked",
                expires_at=NOW + timedelta(hours=1),
            ),
            Grant(
                grant_id="grnt_other_workspace",
                grant_ref="grt_other_workspace",
                workspace_id="ws_other",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=NOW + timedelta(hours=1),
            ),
        )
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        list_status, listed = raw_request(
            server,
            method="GET",
            path="/v1/grants?agent_id=agent_release&status=active",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        agent_status, agent_response = raw_request(
            server,
            method="GET",
            path="/v1/grants",
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert list_status == 200
    assert [grant["grant_ref"] for grant in listed["grants"]] == ["grt_main"]
    assert "audit_event_id" not in listed["grants"][0]
    assert agent_status == 401
    assert agent_response["error"] == "authentication_required"


def test_local_http_agent_key_cannot_issue_grant() -> None:
    svc = InMemoryV1Service()
    svc.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = post_json(
            server,
            path="/v1/grants",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "agent_id": "agent_release",
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
            },
        )

    assert status == 401
    assert response["error"] == "authentication_required"
    assert svc.audit_events == ()


def test_local_http_agent_requests_and_workspace_approves_grant() -> None:
    svc = InMemoryV1Service()
    svc.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        create_status, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
                "reason": "edit the feature readme",
                "task_id": "task_docs",
                "session_id": "session_demo",
                "boundary_id": "bnd_request",
                "requester_runtime": "codex",
                "repo": "vinctor-core",
                "worktree": "feature/docs",
            },
        )
        list_status, listed = raw_request(
            server,
            method="GET",
            path="/v1/grant-requests",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        approve_status, approved = raw_request(
            server,
            method="POST",
            path=f"/v1/grant-requests/{created['request_id']}/approve",
            request_body=json.dumps({"decision_reason": "expected edit"}),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Key": "workspace_key_main",
            },
        )
        enforce_status, enforced = post_json(
            server,
            payload=body(grant_ref=approved["issued_grant_ref"]),
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert create_status == 201
    assert created["status"] == "pending"
    assert created["requester_agent_id"] == "agent_release"
    assert created["target_agent_id"] == "agent_release"
    assert created["task_id"] == "task_docs"
    assert created["session_id"] == "session_demo"
    assert created["boundary_id"] == "bnd_request"
    assert created["requester_runtime"] == "codex"
    assert created["repo"] == "vinctor-core"
    assert created["worktree"] == "feature/docs"
    assert created["routing_hint"] == "manual_review_required"
    assert created["routing_reason"] == "no_matching_rule"
    assert list_status == 200
    assert listed["grant_requests"][0]["request_id"] == created["request_id"]
    assert approve_status == 200
    assert approved["status"] == "approved"
    assert approved["grant"]["grant_ref"] == approved["issued_grant_ref"]
    assert enforce_status == 200
    assert enforced["decision"] == "permit"
    assert [event.event_type for event in svc.audit_events] == [
        "grant_requested",
        "grant_issued",
        "grant_request_approved",
        "action_permitted",
    ]
    assert svc.audit_events[0].boundary_id == "bnd_request"
    assert svc.audit_events[0].runtime == "codex"


def test_local_http_agent_can_only_view_own_grant_request_status() -> None:
    svc = InMemoryV1Service()
    other_request = svc.create_grant_request(
        GrantRequestCreateRequest(
            workspace_id="ws_main",
            requester_agent_id="agent_other",
            requested_scopes=("write:repo/feature/readme",),
            requested_ttl_seconds=3600,
            reason="other agent request",
            request_id="grq_other",
        ),
        now=NOW,
    )
    assert other_request.request is not None

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        create_status, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
                "reason": "edit the feature readme",
            },
        )
        own_status, own = raw_request(
            server,
            method="GET",
            path=f"/v1/grant-requests/{created['request_id']}",
            headers={"X-Agent-Key": "agent_key_main"},
        )
        other_status, other = raw_request(
            server,
            method="GET",
            path="/v1/grant-requests/grq_other",
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert create_status == 201
    assert own_status == 200
    assert own["request_id"] == created["request_id"]
    assert "decided_by" not in own
    assert other_status == 404
    assert other["error"] == "grant_request_not_found"


def test_local_http_workspace_auto_approves_matching_grant_request() -> None:
    svc = InMemoryV1Service()
    svc.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        rule_status, rule = post_json(
            server,
            path="/v1/auto-approval-rules",
            headers={"X-Workspace-Key": "workspace_key_main"},
            payload={
                "name": "Feature docs auto approval",
                "target_agent_id": "agent_release",
                "allowed_scopes": ["write:repo/feature/*"],
                "max_ttl_seconds": 3600,
            },
        )
        create_status, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
                "reason": "edit the feature readme",
            },
        )
        auto_status, auto_approved = raw_request(
            server,
            method="POST",
            path=f"/v1/grant-requests/{created['request_id']}/auto-approve",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        enforce_status, enforced = post_json(
            server,
            payload=body(grant_ref=auto_approved["issued_grant_ref"]),
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert rule_status == 201
    assert create_status == 201
    assert created["routing_hint"] == "auto_approval_available"
    assert created["routing_reason"] == "auto_approval_match"
    assert auto_status == 200
    assert auto_approved["status"] == "approved"
    assert auto_approved["decision_reason"] == f"auto_approval_rule:{rule['rule_id']}"
    assert auto_approved["auto_approval"] == {
        "decision": "approved",
        "reason": "grant_request_auto_approved",
        "rule_id": rule["rule_id"],
    }
    assert auto_approved["grant"]["grant_ref"] == auto_approved["issued_grant_ref"]
    assert enforce_status == 200
    assert enforced["decision"] == "permit"
    assert [event.event_type for event in svc.audit_events] == [
        "grant_requested",
        "grant_issued",
        "grant_request_auto_approved",
        "action_permitted",
    ]


def test_local_http_auto_approve_leaves_non_matching_request_pending() -> None:
    svc = InMemoryV1Service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        create_status, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
                "reason": "edit the feature readme",
            },
        )
        auto_status, response = raw_request(
            server,
            method="POST",
            path=f"/v1/grant-requests/{created['request_id']}/auto-approve",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert create_status == 201
    assert auto_status == 200
    assert response["status"] == "pending"
    assert response["issued_grant_ref"] is None
    assert response["auto_approval"] == {
        "decision": "would_not_approve",
        "reason": "no_matching_rule",
    }
    assert [event.event_type for event in svc.audit_events] == ["grant_requested"]


def test_local_http_agent_key_cannot_approve_grant_request() -> None:
    svc = InMemoryV1Service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        create_status, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
                "reason": "edit the feature readme",
            },
        )
        approve_status, response = raw_request(
            server,
            method="POST",
            path=f"/v1/grant-requests/{created['request_id']}/approve",
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert create_status == 201
    assert approve_status == 401
    assert response["error"] == "authentication_required"
    assert [event.event_type for event in svc.audit_events] == ["grant_requested"]


def test_local_http_agent_key_cannot_auto_approve_grant_request() -> None:
    svc = InMemoryV1Service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        create_status, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
                "reason": "edit the feature readme",
            },
        )
        auto_status, response = raw_request(
            server,
            method="POST",
            path=f"/v1/grant-requests/{created['request_id']}/auto-approve",
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert create_status == 201
    assert auto_status == 401
    assert response["error"] == "authentication_required"
    assert [event.event_type for event in svc.audit_events] == ["grant_requested"]


def test_local_http_workspace_rejects_grant_request() -> None:
    svc = InMemoryV1Service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        _, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/readme"],
                "ttl_seconds": 3600,
                "reason": "edit the feature readme",
            },
        )
        reject_status, rejected = raw_request(
            server,
            method="POST",
            path=f"/v1/grant-requests/{created['request_id']}/reject",
            request_body=json.dumps({"decision_reason": "not needed"}),
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Key": "workspace_key_main",
            },
        )

    assert reject_status == 200
    assert rejected["status"] == "rejected"
    assert rejected["issued_grant_ref"] is None
    assert [event.event_type for event in svc.audit_events] == [
        "grant_requested",
        "grant_request_rejected",
    ]


def test_local_http_workspace_lists_audit_events_with_allowlisted_fields() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        post_json(
            server,
            payload=body(action="send", resource="email/external"),
        )
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?limit=5",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert len(response["audit_events"]) == 1
    event = response["audit_events"][0]
    assert event == {
        "event_id": svc.audit_events[0].event_id,
        "event_type": "action_denied",
        "decision": "deny",
        "reason": "action_denied",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "grant_id": "grnt_main",
        "grant_ref": "grt_main",
        "action": "send",
        "resource": "email/external",
        "scope_attempted": "send:email/external",
        "scope_matched": None,
        "boundary_id": None,
        "runtime": None,
        "boundary_type": None,
        "created_at": NOW.isoformat(),
    }
    assert "event_json" not in event
    assert "raw_prompt" not in event
    assert "raw_tool_input" not in event
    assert "raw_command" not in event
    assert "key_hash" not in event
    assert "db_path" not in event


def test_local_http_workspace_gets_single_audit_event() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        post_json(server)
        event_id = svc.audit_events[0].event_id
        status, response = raw_request(
            server,
            method="GET",
            path=f"/v1/audit-events/{event_id}",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert response["event_id"] == event_id
    assert response["decision"] == "permit"
    assert "event_json" not in response


def test_local_http_audit_events_require_workspace_key() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events",
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert status == 401
    assert response["error"] == "authentication_required"


def test_local_http_audit_events_filter_by_request_id() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        _, created = post_json(
            server,
            path="/v1/grant-requests",
            headers={"X-Agent-Key": "agent_key_main"},
            payload={
                "scopes": ["write:repo/feature/*"],
                "ttl_seconds": 300,
                "reason": "write docs",
            },
        )
        request_id = created["request_id"]
        status, response = raw_request(
            server,
            method="GET",
            path=f"/v1/audit-events?request_id={request_id}",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert [event["event_type"] for event in response["audit_events"]] == [
        "grant_requested"
    ]
    assert response["audit_events"][0]["grant_ref"] == request_id


def test_local_http_audit_events_filter_by_agent_id() -> None:
    svc = service()
    svc.audit_writer.write(
        AuditEvent(
            event_id="evt_other",
            event_type="action_denied",
            decision="deny",
            reason="action_denied",
            workspace_id="ws_main",
            agent_id="agent_other",
            grant_id="grnt_other",
            grant_ref="grt_other",
            action="send",
            resource="email/external",
            scope_attempted="send:email/external",
            scope_matched=None,
            boundary_id=None,
            runtime=None,
            boundary_type=None,
            created_at=NOW,
        )
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        post_json(server)
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?agent_id=agent_release",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert [event["agent_id"] for event in response["audit_events"]] == ["agent_release"]


def test_local_http_audit_events_rejects_event_alias() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?event=action_denied",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 400
    assert response["error"] == "invalid_request"
    assert response["reason"] == "unexpected query parameter: event"


def test_local_http_workspace_manages_auto_approval_rules() -> None:
    svc = InMemoryV1Service()
    payload = {
        "name": "CI auto approval",
        "target_agent_id": "agent_release",
        "allowed_scopes": ["write:repo/feature/*"],
        "max_ttl_seconds": 3600,
    }

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        create_status, created = post_json(
            server,
            path="/v1/auto-approval-rules",
            headers={"X-Workspace-Key": "workspace_key_main"},
            payload=payload,
        )
        list_status, listed = raw_request(
            server,
            method="GET",
            path="/v1/auto-approval-rules",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        agent_create_status, agent_create = post_json(
            server,
            path="/v1/auto-approval-rules",
            headers={"X-Agent-Key": "agent_key_main"},
            payload=payload,
        )
        disable_status, disabled = raw_request(
            server,
            method="POST",
            path=f"/v1/auto-approval-rules/{created['rule_id']}/disable",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert create_status == 201
    assert created["workspace_id"] == "ws_main"
    assert created["status"] == "active"
    assert list_status == 200
    assert listed["auto_approval_rules"] == [created]
    assert agent_create_status == 401
    assert agent_create["error"] == "authentication_required"
    assert disable_status == 200
    assert disabled["rule_id"] == created["rule_id"]
    assert disabled["status"] == "disabled"


def get_text(
    server: ThreadingHTTPServer,
    *,
    path: str,
) -> tuple[int, str]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    conn.request("GET", path)
    response = conn.getresponse()
    raw = response.read().decode("utf-8")
    conn.close()
    return response.status, raw


def test_local_http_metrics_endpoint_records_requests_and_decisions() -> None:
    svc = service()
    metrics = Metrics()

    with running_server(svc, metrics=metrics) as server:
        permit_status, _ = post_json(server)
        deny_status, _ = post_json(
            server,
            payload=body(action="send", resource="email/external"),
        )
        metrics_status, metrics_text = get_text(server, path="/metrics")

    assert permit_status == 200
    assert deny_status == 403
    assert metrics_status == 200
    assert "# TYPE vinctor_http_requests_total counter" in metrics_text
    assert 'path="/v1/enforce"' in metrics_text
    assert 'vinctor_enforce_decisions_total{decision="permit"} 1' in metrics_text
    assert 'vinctor_enforce_decisions_total{decision="deny"} 1' in metrics_text
    # Leak-free: only method/path/status/decision codes appear — never the
    # agent key, grant ref, agent id, workspace id, or any raw body value.
    for secret in (
        "agent_key_main",
        "grt_main",
        "grnt_main",
        "agent_release",
        "ws_main",
        "email/external",
    ):
        assert secret not in metrics_text


def test_local_http_metrics_collapses_ids_and_unknown_paths_to_route_templates() -> (
    None
):
    svc = service()
    metrics = Metrics()

    with running_server(svc, metrics=metrics) as server:
        # Prefix route carrying a grant id (no auth needed: the label is
        # captured in finally regardless of the 401 auth result).
        grant_status, _ = get_text(server, path="/v1/grants/grnt_main")
        # Arbitrary unknown path carrying a junk segment.
        junk_status, _ = get_text(server, path="/xyz/AAAA_SECRET")
        metrics_status, metrics_text = get_text(server, path="/metrics")

    assert grant_status == 401
    assert junk_status == 404
    assert metrics_status == 200
    # The id segment is collapsed to the fixed route template; the raw id
    # and the junk segment never reach a metric label.
    assert 'path="/v1/grants/:id"' in metrics_text
    assert 'path="other"' in metrics_text
    for leaked in (
        "grnt_main",
        "grt_main",
        "AAAA_SECRET",
        "/v1/grants/grnt_main",
        "/xyz/AAAA_SECRET",
    ):
        assert leaked not in metrics_text


def test_local_http_metrics_endpoint_absent_without_metrics() -> None:
    svc = service()

    with running_server(svc) as server:
        post_json(server)
        status, response = get_text(server, path="/metrics")

    assert status == 404
    assert json.loads(response)["error"] == "not_found"


def _raw_socket_post(
    server: ThreadingHTTPServer,
    *,
    content_length: str,
    body: bytes,
    path: str = "/v1/enforce",
) -> tuple[int, dict[str, Any]]:
    """Send a hand-rolled POST so Content-Length can lie about the body length.

    Returns (status, parsed-json-body). Used to exercise the bounded-body guard
    without actually transmitting a huge payload.
    """
    host, port = server.server_address
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "X-Agent-Key: agent_key_main\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {content_length}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("ascii") + body
    sock = socket.create_connection((host, port), timeout=5)
    try:
        sock.sendall(request)
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        sock.close()
    raw = b"".join(chunks)
    head, _, payload = raw.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("ascii")
    status = int(status_line.split(" ", 2)[1])
    return status, json.loads(payload.decode("utf-8"))


def test_local_http_rejects_oversized_content_length_before_reading() -> None:
    # A Content-Length far above the cap must be rejected with 413 BEFORE the
    # server attempts to buffer it. We advertise 10 MB but send only a few bytes;
    # a server that tried rfile.read(10_000_000) would block until our socket
    # timeout instead of returning a clean response.
    svc = service()

    with running_server(svc) as server:
        status, response = _raw_socket_post(
            server,
            content_length=str(10_000_000),
            body=b"{}",
        )

    assert status == 413
    assert response["error"] == "payload_too_large"
    assert svc.audit_events == ()


def test_local_http_rejects_negative_content_length() -> None:
    # A negative Content-Length must be rejected cleanly and must NOT reach
    # rfile.read(-1), which would drain the socket.
    svc = service()

    with running_server(svc) as server:
        status, response = _raw_socket_post(
            server,
            content_length="-1",
            body=b"",
        )

    assert status in (400, 413)
    assert response["error"] in ("payload_too_large", "invalid_request")
    assert svc.audit_events == ()


def test_local_http_accepts_normal_small_body() -> None:
    # Regression: a normal small JSON body still works after the cap is added.
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server)

    assert status == 200
    assert response["decision"] == "permit"


def test_v1_handler_has_finite_timeout() -> None:
    handler = create_v1_http_handler(
        service=service(),
        agent_identities=identities(),
    )
    assert handler.timeout is not None
    assert handler.timeout > 0


def test_local_http_invalid_pop_skew_does_not_500_delegated_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An invalid VINCTOR_SUBJECT_TOKEN_POP_SKEW_SECONDS must not 500 the
    # delegated enforce path per request: it is validated once / falls back to
    # the documented default rather than crashing on an unguarded int().
    monkeypatch.setenv("VINCTOR_SUBJECT_TOKEN_POP_SKEW_SECONDS", "30s")
    svc = service()

    with running_server(svc, pep_keys=pep_identities()) as server:
        status, response = post_json(
            server,
            payload=delegated_body(),
            headers={"X-PEP-Key": "pep_key_main"},
            path="/v1/enforce/delegated",
        )

    assert status != 500
    assert response.get("error") != "internal_error"
    assert status == 200
    assert response["decision"] == "permit"
