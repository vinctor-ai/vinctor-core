from datetime import UTC, datetime, timedelta

from vinctor_core import BoundaryRegistrationInput, Grant, register_boundary
from vinctor_service import (
    AgentIdentity,
    InMemoryV1Service,
    V1HttpResponse,
    handle_v1_enforce_http,
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


def body(
    *,
    grant_ref: str = "grt_main",
    action: str = "write",
    resource: str = "repo/feature/readme",
) -> dict[str, str]:
    return {"grant_ref": grant_ref, "action": action, "resource": resource}


def call(
    service_instance: InMemoryV1Service,
    *,
    headers: dict[str, str] | None = None,
    request_body: object | None = None,
) -> V1HttpResponse:
    return handle_v1_enforce_http(
        headers={"X-Agent-Key": "agent_key_main"} if headers is None else headers,
        body=body() if request_body is None else request_body,
        agent_identities=identities(),
        service=service_instance,
        now=NOW,
    )


def test_v1_http_permit_response_matches_contract() -> None:
    svc = service()

    response = call(svc)

    assert response.status_code == 200
    assert response.body == {
        "decision": "permit",
        "grant_id": "grnt_main",
        "agent_id": "agent_release",
        "scope_matched": "write:repo/feature/*",
        "audit_event_id": svc.audit_events[0].event_id,
    }


def test_v1_http_deny_response_matches_contract() -> None:
    svc = service()

    response = call(svc, request_body=body(action="send", resource="email/external"))

    assert response.status_code == 403
    assert response.body["decision"] == "deny"
    assert response.body["error"] == "action_denied"
    assert response.body["audit_event_id"] == svc.audit_events[0].event_id


def test_v1_http_requires_agent_key() -> None:
    svc = service()

    response = call(svc, headers={}, request_body=body())

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"
    # ADR 0008: the authentication failure is recorded (rate-limited) for the operator.
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_v1_http_rejects_unknown_agent_key() -> None:
    svc = service()

    response = call(svc, headers={"X-Agent-Key": "unknown"}, request_body=body())

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"
    # ADR 0008: the bad-credential probe is recorded (rate-limited) for the operator.
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_v1_http_rejects_missing_required_body_field() -> None:
    svc = service()

    response = call(svc, request_body={"grant_ref": "grt_main", "action": "write"})

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert svc.audit_events == ()


def test_v1_http_rejects_extra_body_field() -> None:
    svc = service()

    response = call(svc, request_body={**body(), "boundary_id": "bnd_body"})

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert svc.audit_events == ()


def test_v1_http_rejects_non_string_fields() -> None:
    svc = service()

    response = call(svc, request_body={**body(), "resource": 123})

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert svc.audit_events == ()


def test_v1_http_passes_boundary_header_to_service() -> None:
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
        boundary_id="bnd_header",
    )

    response = call(
        svc,
        headers={
            "X-Agent-Key": "agent_key_main",
            "X-Vinctor-Boundary-Id": boundary.boundary_id,
        },
    )

    assert response.status_code == 200
    assert svc.audit_events[0].boundary_id == "bnd_header"
    assert svc.audit_events[0].runtime == "claude-code"
    assert svc.audit_events[0].boundary_type == "pretooluse"


def test_v1_http_headers_are_case_insensitive() -> None:
    svc = service()

    response = call(
        svc,
        headers={"x-agent-key": "agent_key_main"},
        request_body=body(),
    )

    assert response.status_code == 200
    assert response.body["decision"] == "permit"


def test_v1_http_unknown_grant_uses_v1_response_without_audit() -> None:
    svc = service()

    response = call(svc, request_body=body(grant_ref="grt_missing"))

    assert response.status_code == 404
    assert response.body["error"] == "grant_not_found"
    assert "decision" not in response.body
    assert svc.audit_events == ()
