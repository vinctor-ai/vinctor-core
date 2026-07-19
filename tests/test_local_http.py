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
from vinctor_core.audit import (
    EVENT_AUTH_FAILED,
    REASON_AGENT_GRANT_MISMATCH,
    REASON_AUTH_FAILED,
    build_rejection_audit_event,
)
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
    readiness_check=None,
    request_scope=None,
) -> Iterator[ThreadingHTTPServer]:
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service_instance,
        agent_identities=identities(),
        workspace_identities=workspace_keys,
        pep_identities=pep_keys,
        clock=lambda: NOW,
        metrics=metrics,
        readiness_check=readiness_check,
        request_scope=request_scope,
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


def post_with_xff_headers(
    server: ThreadingHTTPServer,
    forwarded_values: tuple[str, ...],
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    request_body = json.dumps(body()).encode("utf-8")
    conn.putrequest("POST", "/v1/enforce")
    conn.putheader("Content-Type", "application/json")
    conn.putheader("Content-Length", str(len(request_body)))
    conn.putheader("X-Agent-Key", "agent_key_main")
    for value in forwarded_values:
        conn.putheader("X-Forwarded-For", value)
    conn.endheaders(request_body)
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


def test_local_http_server_header_hides_python_version() -> None:
    # Red-team NOTE (Codex 2026-07-12): the Server header leaked the exact
    # runtime patch version ("VinctorLocalHTTP/0.1 Python/3.11.15"). Suppress the
    # Python/<version> suffix so the banner discloses no runtime detail.
    svc = service()
    with running_server(svc) as server:
        host, port = server.server_address
        conn = HTTPConnection(host, port, timeout=5)
        conn.request("POST", "/v1/enforce", body=json.dumps(body()),
                     headers={"Content-Type": "application/json", "X-Agent-Key": "agent_key_main"})
        resp = conn.getresponse()
        server_header = resp.getheader("Server") or ""
        resp.read()
        conn.close()

    assert "Python/" not in server_header, server_header
    assert "VinctorLocalHTTP" in server_header


@pytest.mark.parametrize(
    ("ready", "status", "body_status"),
    [(True, 200, "ready"), (False, 503, "unavailable")],
)
def test_readiness_reflects_storage_check(
    ready: bool,
    status: int,
    body_status: str,
) -> None:
    with running_server(service(), readiness_check=lambda: ready) as server:
        response_status, response = raw_request(server, method="GET", path="/readyz")

    assert response_status == status
    assert response == {
        "status": body_status,
        "service": "vinctor-service",
    }


def test_readiness_fails_closed_when_storage_check_raises() -> None:
    def fail() -> bool:
        raise RuntimeError("database unavailable")

    with running_server(service(), readiness_check=fail) as server:
        status, response = raw_request(server, method="GET", path="/readyz")

    assert status == 503
    assert response["status"] == "unavailable"


def test_local_http_service_permits_v1_enforce_request() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server)

    assert status == 200
    assert response["decision"] == "permit"
    # No-disclosure: grant/agent identifiers and the matched scope are recorded
    # in the operator audit, never in the agent-facing response body.
    assert set(response) == {"decision", "audit_event_id"}
    assert len(svc.audit_events) == 1
    assert svc.audit_events[0].grant_id == "grnt_main"
    assert svc.audit_events[0].agent_id == "agent_release"
    assert svc.audit_events[0].scope_matched == "write:repo/feature/*"


def test_local_http_service_simulates_deny_without_returning_forbidden() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(
            server,
            path="/v1/simulate",
            payload=body(resource="repo/other/readme"),
        )

    assert status == 200
    assert response["status"] == "simulated"
    assert response["would_decision"] == "deny"
    assert svc.audit_events[0].event_type == "action_would_deny"


def test_local_http_service_records_observation_without_grant() -> None:
    svc = InMemoryV1Service()

    with running_server(svc) as server:
        status, response = post_json(
            server,
            path="/v1/observe",
            payload={
                "classification": "mapped",
                "action": "read",
                "resource": "repo/feature/readme",
            },
        )

    assert status == 200
    assert response["status"] == "recorded"
    assert response["audit_event_id"] == svc.audit_events[0].event_id
    assert svc.audit_events[0].event_type == "action_observed"


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
    assert disabled_enforce["error"] == "boundary_unavailable"
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


def test_local_http_out_of_bounds_issuance_returns_actionable_detail() -> None:
    svc = InMemoryV1Service()
    svc.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response_body = post_json(
            server,
            path="/v1/grants",
            headers={"X-Workspace-Key": "workspace_key_main"},
            payload={
                "agent_id": "agent_release",
                "scopes": ["execute:deploy/production"],
                "ttl_seconds": 3600,
            },
        )

    assert status == 403
    # error/reason stay low-cardinality codes; detail carries the actionable message.
    assert response_body["error"] == "scope_outside_issuable_bounds"
    assert response_body["reason"] == "scope_outside_issuable_bounds"
    assert "execute:deploy/production" in response_body["detail"]
    assert "write:repo/feature/*" in response_body["detail"]


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
        "enforcing_principal": None,
        "reason_code": None,
        "occurrence_count": None,
        "first_seen_at": None,
        "last_seen_at": None,
        "subject_token_verified": False,
        "token_id": None,
        "event_class": "decision",
    }
    assert "event_json" not in event
    assert "raw_prompt" not in event
    assert "raw_tool_input" not in event
    assert "raw_command" not in event
    assert "key_hash" not in event
    assert "db_path" not in event


def test_local_http_audit_events_surface_proven_delegated_identity() -> None:
    svc = service()

    with running_server(
        svc, workspace_keys=workspace_identities(), pep_keys=pep_identities()
    ) as server:
        minted = svc.mint_subject_token(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            audience="pep_git_host",
            ttl_seconds=300,
            now=NOW,
        )
        assert minted.status == "minted"
        status, response = post_json(
            server,
            payload=delegated_body(),
            headers={"X-PEP-Key": "pep_key_main", "X-Subject-Token": minted.token},
            path="/v1/enforce/delegated",
        )
        assert status == 200
        assert response["decision"] == "permit"
        status, listed = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?event_type=action_permitted",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert len(listed["audit_events"]) == 1
    event = listed["audit_events"][0]
    assert event["enforcing_principal"] == "pep_git_host"
    assert event["subject_token_verified"] is True
    assert event["token_id"] == minted.token_id


def test_local_http_audit_events_surface_rejection_reason_code() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = post_json(server, payload=body(grant_ref="grt_foreign"))
        assert status == 403
        assert response["error"] == "forbidden"
        status, listed = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?event_type=access_rejected",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert len(listed["audit_events"]) == 1
    event = listed["audit_events"][0]
    assert event["reason_code"] == REASON_AGENT_GRANT_MISMATCH
    assert event["reason"] == REASON_AGENT_GRANT_MISMATCH
    assert event["decision"] == "deny"


def test_local_http_audit_event_surfaces_auth_failure_aggregation() -> None:
    svc = service()
    svc.audit_writer.write(
        build_rejection_audit_event(
            reason_code=REASON_AUTH_FAILED,
            workspace_id="ws_main",
            agent_id="",
            created_at=NOW + timedelta(seconds=30),
            event_type=EVENT_AUTH_FAILED,
            action="/v1/enforce",
            scope_attempted="",
            event_id="evt_agg",
            occurrence_count=4,
            first_seen_at=NOW,
            last_seen_at=NOW + timedelta(seconds=30),
        )
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, event = raw_request(
            server,
            method="GET",
            path="/v1/audit-events/evt_agg",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert event["reason_code"] == REASON_AUTH_FAILED
    assert event["occurrence_count"] == 4
    assert event["first_seen_at"] == NOW.isoformat()
    assert event["last_seen_at"] == (NOW + timedelta(seconds=30)).isoformat()


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


def security_audit_event(
    event_id: str,
    *,
    reason_code: str | None = None,
    enforcing_principal: str | None = None,
    subject_token_verified: bool = False,
    event_class: str = "decision",
) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        event_type="action_denied",
        decision="deny",
        reason="action_denied",
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_id="grnt_main",
        grant_ref="grt_main",
        action="send",
        resource="email/external",
        scope_attempted="send:email/external",
        scope_matched=None,
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=NOW,
        enforcing_principal=enforcing_principal,
        reason_code=reason_code,
        subject_token_verified=subject_token_verified,
        event_class=event_class,
    )


def test_local_http_audit_events_filter_by_reason_code() -> None:
    svc = service()
    svc.audit_writer.write(
        security_audit_event("evt_rcode", reason_code="boundary_unregistered")
    )
    svc.audit_writer.write(
        security_audit_event("evt_other", reason_code="agent_key_invalid")
    )
    svc.audit_writer.write(security_audit_event("evt_none"))

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?reason_code=boundary_unregistered",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        all_status, all_response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert [event["event_id"] for event in response["audit_events"]] == ["evt_rcode"]
    # Absent filter: unchanged behavior (all events).
    assert all_status == 200
    assert [event["event_id"] for event in all_response["audit_events"]] == [
        "evt_rcode",
        "evt_other",
        "evt_none",
    ]


def test_local_http_audit_events_filter_by_enforcing_principal() -> None:
    svc = service()
    svc.audit_writer.write(
        security_audit_event("evt_pep", enforcing_principal="pep_git_host")
    )
    svc.audit_writer.write(
        security_audit_event("evt_other", enforcing_principal="pep_mail")
    )
    svc.audit_writer.write(security_audit_event("evt_none"))

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?enforcing_principal=pep_git_host",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 200
    assert [event["event_id"] for event in response["audit_events"]] == ["evt_pep"]


def test_local_http_audit_events_filter_by_subject_token_verified() -> None:
    svc = service()
    svc.audit_writer.write(security_audit_event("evt_proven", subject_token_verified=True))
    svc.audit_writer.write(security_audit_event("evt_unproven"))

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        true_status, true_response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?subject_token_verified=true",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        false_status, false_response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?subject_token_verified=false",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert true_status == 200
    assert [event["event_id"] for event in true_response["audit_events"]] == [
        "evt_proven"
    ]
    assert false_status == 200
    assert [event["event_id"] for event in false_response["audit_events"]] == [
        "evt_unproven"
    ]


def test_local_http_audit_events_rejects_invalid_subject_token_verified() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?subject_token_verified=maybe",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 400
    assert response["error"] == "invalid_request"
    assert response["reason"] == "subject_token_verified must be true or false"


def test_local_http_audit_events_filter_by_event_class() -> None:
    svc = service()
    svc.audit_writer.write(security_audit_event("evt_decision"))
    svc.audit_writer.write(
        security_audit_event("evt_control", event_class="control")
    )

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        control_status, control_response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?event_class=control",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )
        decision_status, decision_response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?event_class=decision",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert control_status == 200
    assert [event["event_id"] for event in control_response["audit_events"]] == [
        "evt_control"
    ]
    assert decision_status == 200
    assert [event["event_id"] for event in decision_response["audit_events"]] == [
        "evt_decision"
    ]


def test_local_http_audit_events_rejects_invalid_event_class() -> None:
    svc = service()

    with running_server(svc, workspace_keys=workspace_identities()) as server:
        status, response = raw_request(
            server,
            method="GET",
            path="/v1/audit-events?event_class=security",
            headers={"X-Workspace-Key": "workspace_key_main"},
        )

    assert status == 400
    assert response["error"] == "invalid_request"
    assert response["reason"] == "event_class must be one of: control, decision"


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


def test_local_http_metrics_records_request_duration_histogram() -> None:
    svc = service()
    metrics = Metrics()

    with running_server(svc, metrics=metrics) as server:
        permit_status, _ = post_json(server)
        metrics_status, metrics_text = get_text(server, path="/metrics")

    assert permit_status == 200
    assert metrics_status == 200
    assert "# TYPE vinctor_http_request_duration_seconds histogram" in metrics_text
    labels = 'method="POST",path="/v1/enforce"'
    assert (
        f'vinctor_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} 1'
        in metrics_text
    )
    assert f"vinctor_http_request_duration_seconds_count{{{labels}}} 1" in metrics_text
    assert f"vinctor_http_request_duration_seconds_sum{{{labels}}}" in metrics_text


def test_local_http_metrics_records_error_counter() -> None:
    svc = service()
    metrics = Metrics()

    with running_server(svc, metrics=metrics) as server:
        permit_status, _ = post_json(server)
        missing_status, _ = get_text(server, path="/nope")
        metrics_status, metrics_text = get_text(server, path="/metrics")

    assert permit_status == 200
    assert missing_status == 404
    assert metrics_status == 200
    assert "# TYPE vinctor_http_errors_total counter" in metrics_text
    assert (
        'vinctor_http_errors_total{error="not_found",method="GET",path="other",status="404"} 1'
        in metrics_text
    )
    # Success responses never increment the error counter: the 200 enforce
    # request above must not appear under vinctor_http_errors_total.
    error_lines = [
        line
        for line in metrics_text.splitlines()
        if line.startswith("vinctor_http_errors_total{")
    ]
    assert error_lines == [
        'vinctor_http_errors_total{error="not_found",method="GET",path="other",status="404"} 1'
    ]


def test_local_http_rate_limited_requests_carry_error_label(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The pre-auth 429 is an error like any other rejection: it must land in
    # the error counter with its own code, not an "unknown" placeholder.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    metrics = Metrics()
    svc = service()

    with running_server(svc, metrics=metrics) as server:
        first = post_json(server)[0]
        over = post_json(server)[0]

    assert first == 200
    assert over == 429
    rendered = metrics.render()
    expected = (
        'vinctor_http_errors_total{error="rate_limited",'
        'method="POST",path="/v1/enforce",status="429"} 1'
    )
    assert expected in rendered


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


def test_local_http_no_rate_limit_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # DEFAULT OFF: with VINCTOR_RATE_LIMIT_PER_MINUTE unset, the limiter is None
    # and no request is ever 429'd, no matter how many arrive from one client.
    monkeypatch.delenv("VINCTOR_RATE_LIMIT_PER_MINUTE", raising=False)
    svc = service()

    with running_server(svc) as server:
        statuses = [post_json(server)[0] for _ in range(10)]

    assert all(status == 200 for status in statuses)
    assert 429 not in statuses


def test_local_http_rate_limits_post_over_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # With a limit of 2/min, the 3rd rapid POST from the same client is 429'd
    # with the generic body and nothing else disclosed.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "2")
    svc = service()

    with running_server(svc) as server:
        first = post_json(server)[0]
        second = post_json(server)[0]
        third_status, third_body = post_json(server)

    assert first == 200
    assert second == 200
    assert third_status == 429
    # Generic body: exactly {"error": "rate_limited"} and nothing else.
    assert third_body == {"error": "rate_limited"}


def test_local_http_xff_is_ignored_without_trusted_proxies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.delenv("VINCTOR_TRUSTED_PROXIES", raising=False)
    svc = service()

    with running_server(svc) as server:
        first = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.1",
            },
        )[0]
        second_status, second_body = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.2",
            },
        )

    assert first == 200
    assert second_status == 429
    assert second_body == {"error": "rate_limited"}


def test_local_http_trusted_proxy_uses_rightmost_nontrusted_hop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("VINCTOR_TRUSTED_PROXIES", "127.0.0.0/8,10.0.0.0/8")
    svc = service()

    with running_server(svc) as server:
        first = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.1, 198.51.100.7, 10.0.0.9",
            },
        )[0]
        forged_status, forged_body = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.2, 198.51.100.7, 10.0.0.9",
            },
        )
        other_client = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.3, 198.51.100.8, 10.0.0.9",
            },
        )[0]

    assert first == 200
    assert forged_status == 429
    assert forged_body == {"error": "rate_limited"}
    assert other_client == 200


def test_local_http_combines_duplicate_xff_headers_before_right_to_left_walk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("VINCTOR_TRUSTED_PROXIES", "127.0.0.0/8,10.0.0.0/8")
    svc = service()

    with running_server(svc) as server:
        first = post_with_xff_headers(
            server,
            ("203.0.113.1", "198.51.100.7, 10.0.0.9"),
        )[0]
        forged_status, forged_body = post_with_xff_headers(
            server,
            ("203.0.113.2", "198.51.100.7, 10.0.0.9"),
        )

    assert first == 200
    assert forged_status == 429
    assert forged_body == {"error": "rate_limited"}


def test_local_http_untrusted_peer_cannot_forge_xff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("VINCTOR_TRUSTED_PROXIES", "10.0.0.0/8")
    svc = service()

    with running_server(svc) as server:
        first = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.1",
            },
        )[0]
        forged_status, forged_body = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.2",
            },
        )

    assert first == 200
    assert forged_status == 429
    assert forged_body == {"error": "rate_limited"}


@pytest.mark.parametrize(
    "forwarded_for",
    ["", ",", "not-an-ip", "198.51.100.1,not-an-ip", "x" * 5000],
)
def test_local_http_malformed_xff_falls_back_to_the_peer_bucket(
    monkeypatch: pytest.MonkeyPatch,
    forwarded_for: str,
) -> None:
    # Unparseable forwarding data must degrade the limiter, not disable it.
    # Raising here would reach _check_rate_limit's catch-all, which answers
    # "allow" — so a client behind a proxy that forwards its X-Forwarded-For
    # unchanged could buy an unlimited budget by sending garbage. Falling back
    # to the peer keeps limiting on a key the socket proves.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.setenv("VINCTOR_TRUSTED_PROXIES", "127.0.0.0/8")
    svc = service()
    headers = {
        "X-Agent-Key": "agent_key_main",
        "X-Forwarded-For": forwarded_for,
    }

    with running_server(svc) as server:
        first = post_json(server, headers=headers)[0]
        second = post_json(server, headers=headers)[0]
        third_status, third_body = post_json(server, headers=headers)

    assert first == 200
    # The limit is 1/minute and both requests landed in the same peer bucket.
    assert second == 429
    assert third_status == 429
    # No 500 anywhere, and the 429 body stays generic (no-disclosure).
    assert third_body == {"error": "rate_limited"}


def test_local_http_trusted_proxy_config_is_parsed_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    monkeypatch.delenv("VINCTOR_TRUSTED_PROXIES", raising=False)
    svc = service()

    with running_server(svc) as server:
        monkeypatch.setenv("VINCTOR_TRUSTED_PROXIES", "127.0.0.0/8")
        first = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.1",
            },
        )[0]
        second = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Forwarded-For": "203.0.113.2",
            },
        )[0]

    assert first == 200
    assert second == 429


def test_local_http_rate_limit_gates_get_too(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The gate covers GET like every other method. Pinned on /readyz
    # deliberately, twice over: the original version of this test pinned the
    # gate on /healthz, which encoded a bug — a 429'd liveness probe reads as
    # a failed liveness probe and restarts a healthy container (see
    # test_local_http_healthz_is_never_rate_limited). /readyz, by contrast,
    # STAYS gated: its failure mode is "stop sending me traffic", which under
    # genuine overload is the correct answer — and it leases a pooled
    # connection by design (#155), so exempting it would reopen the exact
    # unauthenticated pool-occupying flood this change closes (PKA-43).
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "2")
    svc = service()

    with running_server(svc) as server:
        first = get_text(server, path="/readyz")[0]
        second = get_text(server, path="/readyz")[0]
        third_status, third_raw = get_text(server, path="/readyz")

    assert first == 200
    assert second == 200
    assert third_status == 429
    assert json.loads(third_raw) == {"error": "rate_limited"}


def test_local_http_rate_limit_disabled_for_non_positive_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A non-positive / unparseable value disables the limiter (limiter is None).
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "0")
    svc = service()

    with running_server(svc) as server:
        statuses = [post_json(server)[0] for _ in range(5)]

    assert all(status == 200 for status in statuses)
    assert 429 not in statuses


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


def _scope_recorder() -> tuple[list[str], Any]:
    leases: list[str] = []

    @contextmanager
    def scope() -> Iterator[None]:
        leases.append("leased")
        yield

    return leases, scope


def test_healthz_does_not_lease_a_request_scope() -> None:
    # Liveness must never queue for a pooled connection. /healthz does not touch
    # the database, yet it was wrapped in the same request scope as real
    # traffic, so a saturated pool stalled the probe: a dogfood run measured
    # /healthz at 0.25ms idle but p99 1.0s under 64 concurrent writers. That is
    # long enough for an orchestrator's default 1s liveness timeout to kill a
    # healthy-but-busy process — and the restart makes the contention worse.
    leases, scope = _scope_recorder()

    with running_server(service(), request_scope=scope) as server:
        status, _ = get_text(server, path="/healthz")

    assert status == 200
    assert leases == []


def test_metrics_does_not_lease_a_request_scope() -> None:
    # Same reasoning as /healthz: metrics are in-process counters, so reporting
    # them must not wait behind database traffic for a pooled connection.
    leases, scope = _scope_recorder()

    with running_server(service(), metrics=Metrics(), request_scope=scope) as server:
        status, _ = get_text(server, path="/metrics")

    assert status == 200
    assert leases == []


def test_enforce_still_leases_a_request_scope() -> None:
    # Positive control: exempting the database-free routes must not switch the
    # scope off for real traffic, which is what actually needs the connection.
    leases, scope = _scope_recorder()

    with running_server(service(), request_scope=scope) as server:
        status, _ = post_json(server)

    assert status == 200
    assert leases == ["leased"]


def _status_only_request(server: ThreadingHTTPServer, method: str, path: str) -> int:
    """Send a bare request and return only the status code.

    Unlike raw_request this never parses the response body, so it works for any
    method — including a future do_HEAD, whose responses carry no body.
    """
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    conn.request(method, path)
    response = conn.getresponse()
    response.read()
    conn.close()
    return response.status


@pytest.mark.parametrize("method", ["PUT", "PATCH", "DELETE"])
def test_local_http_rate_limit_gates_put_patch_delete_too(
    monkeypatch: pytest.MonkeyPatch,
    method: str,
) -> None:
    # PKA-43: the pre-auth volume gate covered POST and GET only, so an
    # unauthenticated PUT/PATCH/DELETE flood sailed straight past
    # VINCTOR_RATE_LIMIT_PER_MINUTE. Every method must hit the same gate.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    svc = service()

    with running_server(svc) as server:
        first_status, _ = raw_request(server, method=method)
        over_status, over_body = raw_request(server, method=method)

    # Within budget the request is routed and refused by the route (405);
    # beyond it the gate answers 429 with the generic no-disclosure body.
    assert first_status == 405
    assert over_status == 429
    assert over_body == {"error": "rate_limited"}


def test_local_http_rate_limit_gates_every_do_method(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # PKA-43 regression guard. The hole existed because the gate was opt-in per
    # do_* method, so this test enumerates the do_* methods off the served
    # handler class instead of hardcoding today's list: a future do_HEAD /
    # do_OPTIONS that skips the gated dispatch chokepoint fails here by
    # construction, not by someone remembering to extend a list.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    svc = service()

    with running_server(svc) as server:
        methods = sorted(
            name.removeprefix("do_")
            for name in dir(server.RequestHandlerClass)
            if name.startswith("do_")
        )
        # Sanity: introspection really found the surface this server answers.
        assert set(methods) >= {"DELETE", "GET", "PATCH", "POST", "PUT"}

        # One allowed request burns the whole 1/minute budget for 127.0.0.1
        # (/readyz, not /healthz: the liveness path is exempt and consumes no
        # budget)...
        assert _status_only_request(server, "GET", "/readyz") == 200
        # ...after which every dispatchable method must be turned away.
        over_limit = {
            method: _status_only_request(server, method, "/v1/enforce")
            for method in methods
        }

    assert over_limit == {method: 429 for method in methods}


def test_local_http_rate_limited_request_does_not_lease_a_request_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # PKA-43, second half: an un-gated PUT to a database path leased one of the
    # pool's 8 connections just to be told 405, so the flood the limiter exists
    # to stop also occupied the pool. An over-limit request must be turned away
    # before the request scope opens.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    leases, scope = _scope_recorder()

    with running_server(service(), request_scope=scope) as server:
        first_status, _ = raw_request(server, method="PUT")
        over_status, over_body = raw_request(server, method="PUT")

    # Within budget: routed as before, which leases (and 405s) — unchanged.
    assert first_status == 405
    # Over budget: 429 without ever touching the pool.
    assert over_status == 429
    assert over_body == {"error": "rate_limited"}
    assert leases == ["leased"]


def test_local_http_rate_limited_requests_are_observed_in_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Deliberate (PKA-43): 429s are recorded in metrics and the access log like
    # every other pre-auth rejection (401/404/405/413). An availability control
    # you cannot see firing is operationally useless during the exact flood it
    # exists for. The counters are read off the Metrics object directly — a
    # GET /metrics over the wire would itself be over the limit here.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    metrics = Metrics()
    svc = service()

    with running_server(svc, metrics=metrics) as server:
        first = post_json(server)[0]
        over = post_json(server)[0]

    assert first == 200
    assert over == 429
    rendered = metrics.render()
    assert (
        'vinctor_http_requests_total{method="POST",path="/v1/enforce",status="429"} 1'
        in rendered
    )


def test_local_http_healthz_is_never_rate_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Liveness must answer even when a source's budget is exhausted. A 429'd
    # /healthz reads as a FAILED liveness probe, and the restart it triggers
    # removes capacity under exactly the load the limiter exists to survive —
    # the same restart-loop failure mode #155 closed for the connection pool.
    # docs/api-contract.md is explicit: "/healthz ... remains successful while
    # the HTTP process is running." The first revision of this change gated
    # /healthz (and test_local_http_rate_limit_gates_get_too pinned it); that
    # was wrong, and this test pins the correction.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    svc = service()

    with running_server(svc) as server:
        burn = get_text(server, path="/readyz")[0]
        exhausted = get_text(server, path="/readyz")[0]
        healthz_statuses = [get_text(server, path="/healthz")[0] for _ in range(5)]
        healthz_body = json.loads(get_text(server, path="/healthz")[1])

    assert burn == 200
    # Control: the budget really is exhausted for this source...
    assert exhausted == 429
    # ...yet liveness keeps answering, and with the full health body.
    assert healthz_statuses == [200, 200, 200, 200, 200]
    assert healthz_body["status"] == "ok"


def test_local_http_healthz_non_get_is_rate_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Only the liveness GET is exempt from the volume gate. A non-GET
    # /healthz has no liveness meaning — it previously slipped through the
    # exemption for free (the exemption was by path alone, for any method),
    # silently reopening an unauthenticated path around the pre-auth gate.
    # Once a source's budget is exhausted, POST/PUT/PATCH/DELETE to /healthz
    # must be gated exactly like any other route; plain GET must keep
    # answering regardless.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    svc = service()

    with running_server(svc) as server:
        burn = raw_request(server, method="POST", path="/healthz")[0]
        exhausted_post = raw_request(server, method="POST", path="/healthz")[0]
        exhausted_put = raw_request(server, method="PUT", path="/healthz")[0]
        exhausted_patch = raw_request(server, method="PATCH", path="/healthz")[0]
        exhausted_delete = raw_request(server, method="DELETE", path="/healthz")[0]
        get_still_answers = get_text(server, path="/healthz")[0]

    # First non-GET request still consumes budget (it is not exempt) and
    # reaches the health handler's method_not_allowed arm.
    assert burn == 405
    # Control: the budget really is exhausted for this source, and non-GET
    # /healthz is gated like everything else — no free pass.
    assert exhausted_post == 429
    assert exhausted_put == 429
    assert exhausted_patch == 429
    assert exhausted_delete == 429
    # ...yet the actual liveness probe (GET) still keeps answering.
    assert get_still_answers == 200


def test_local_http_metrics_stays_rate_limited(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Deliberate (PKA-43 revision): /metrics KEEPS the volume gate. It is an
    # operator-facing endpoint, not a probe — a 429'd scrape is a missed
    # sample, not a container restart — and the limiter is per-source, so an
    # attacker cannot spend the scraper's budget. Exemptions from a pre-auth
    # gate need a failure-mode justification like /healthz's; /metrics has
    # none, and render() takes the same lock every request's counter
    # increment needs, so unlimited unauthenticated scraping is free
    # contention.
    monkeypatch.setenv("VINCTOR_RATE_LIMIT_PER_MINUTE", "1")
    svc = service()

    with running_server(svc, metrics=Metrics()) as server:
        first = get_text(server, path="/metrics")[0]
        second_status, second_raw = get_text(server, path="/metrics")

    assert first == 200
    assert second_status == 429
    assert json.loads(second_raw) == {"error": "rate_limited"}
