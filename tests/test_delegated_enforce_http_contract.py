from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_service import (
    InMemoryV1Service,
    V1HttpResponse,
)
from vinctor_service.v1_http import PepIdentity, handle_v1_delegated_enforce_http

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant(
    *,
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
) -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def service(*grants: Grant) -> InMemoryV1Service:
    return InMemoryV1Service(grants=grants or (grant(),))


def pep_identities() -> dict[str, PepIdentity]:
    return {
        "pep_key_main": PepIdentity(workspace_id="ws_main", pep_id="pep_git_host"),
        "pep_key_other": PepIdentity(workspace_id="ws_other", pep_id="pep_other_host"),
    }


def body(
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


def call(
    svc: InMemoryV1Service,
    *,
    headers: dict[str, str] | None = None,
    request_body: object | None = None,
) -> V1HttpResponse:
    return handle_v1_delegated_enforce_http(
        headers={"X-PEP-Key": "pep_key_main"} if headers is None else headers,
        body=body() if request_body is None else request_body,
        pep_identities=pep_identities(),
        service=svc,
        now=NOW,
    )


def test_delegated_http_permit() -> None:
    svc = service()

    response = call(svc)

    assert response.status_code == 200
    assert response.body["decision"] == "permit"
    assert response.body["agent_id"] == "agent_release"
    assert svc.audit_events[0].enforcing_principal == "pep_git_host"


def test_delegated_http_requires_pep_key() -> None:
    svc = service()

    response = call(svc, headers={}, request_body=body())

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"
    # ADR 0008: the authentication failure is recorded (rate-limited) for the operator.
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_delegated_http_rejects_agent_key_as_pep() -> None:
    svc = service()

    # An agent key value is not a PEP key; it does not resolve to a PEP identity.
    response = call(
        svc,
        headers={"X-PEP-Key": "aak_some_agent_key"},
        request_body=body(),
    )

    assert response.status_code == 401
    assert response.body["error"] == "authentication_required"
    # ADR 0008: the bad-credential probe is recorded (rate-limited) for the operator.
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_delegated_http_pep_cannot_cross_workspace() -> None:
    svc = service(grant(workspace_id="ws_other"))

    # PEP authenticated for ws_main asserts a subject in ws_other.
    response = call(
        svc,
        headers={"X-PEP-Key": "pep_key_main"},
        request_body=body(workspace_id="ws_other"),
    )

    assert response.status_code == 403
    assert response.body["error"] == "forbidden"
    # ADR 0008: the cross-workspace PEP attempt is audited for the operator (no leak).
    assert len(svc.audit_events) == 1
    assert svc.audit_events[0].reason == "agent_grant_mismatch"


def test_delegated_http_subject_must_match_grant_owner() -> None:
    svc = service(grant(agent_id="agent_release"))

    response = call(svc, request_body=body(agent_id="agent_other"))

    assert response.status_code == 403
    assert response.body["error"] == "forbidden"
    # ADR 0008: the subject-vs-grant-owner mismatch is audited (no leak).
    assert len(svc.audit_events) == 1
    assert svc.audit_events[0].reason == "agent_grant_mismatch"


def test_delegated_http_rejects_missing_subject_field() -> None:
    svc = service()

    incomplete = body()
    del incomplete["agent_id"]
    response = call(svc, request_body=incomplete)

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert svc.audit_events == ()
