from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread
from typing import Any

from vinctor_core import BoundaryRegistrationInput, Grant, register_boundary
from vinctor_service import (
    AgentIdentity,
    InMemoryV1Service,
    WorkspaceIdentity,
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


@contextmanager
def running_server(
    service_instance: InMemoryV1Service,
    *,
    workspace_keys: dict[str, WorkspaceIdentity] | None = None,
) -> Iterator[ThreadingHTTPServer]:
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service_instance,
        agent_identities=identities(),
        workspace_identities=workspace_keys,
        clock=lambda: NOW,
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
    assert svc.audit_events == ()


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
