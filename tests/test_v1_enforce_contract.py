from datetime import UTC, datetime, timedelta

from vinctor_core import (
    BoundaryRegistry,
    Grant,
)
from vinctor_core.audit import AuditEvent
from vinctor_service import V1EnforceRequest, enforce_v1_contract

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant(
    *,
    grant_id: str = "grnt_main",
    grant_ref: str = "grt_main",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    scopes: tuple[str, ...] = ("write:repo/feature/*",),
    status: str = "active",
    expires_at: datetime | None = None,
) -> Grant:
    return Grant(
        grant_id=grant_id,
        grant_ref=grant_ref,
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=scopes,
        status=status,
        expires_at=expires_at or NOW + timedelta(hours=1),
    )


def request(
    *,
    grant_ref: str = "grt_main",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    action: str = "write",
    resource: str = "repo/feature/readme",
    boundary_id: str | None = None,
) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_ref=grant_ref,
        action=action,
        resource=resource,
        boundary_id=boundary_id,
    )


class AuditRecorder:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


def test_v1_enforce_permit_writes_audit_before_returning_decision() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].decision == "permit"
    assert audit.events[0].scope_matched == "write:repo/feature/*"


def test_v1_enforce_scope_deny_writes_audit_event() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(action="send", resource="email/external"),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "action_denied"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].reason == "action_denied"


def test_v1_enforce_grant_not_found_returns_404_without_audit() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 404
    assert response.error == "grant_not_found"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_cross_agent_misuse_returns_forbidden_without_audit() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(agent_id="agent_other"),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_wrong_workspace_returns_forbidden_without_audit() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(workspace_id="ws_other"),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_invalid_action_maps_to_scope_invalid_without_audit() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(action="push", resource="repo/main"),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 400
    assert response.error == "scope_invalid"
    assert "push" in response.reason
    assert "write" in response.reason
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_invalid_resource_maps_to_scope_invalid_without_audit() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(resource="repo"),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 400
    assert response.error == "scope_invalid"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_revoked_grant_writes_deny_audit() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(),
        grants=(grant(status="revoked"),),
        now=NOW,
        write_audit=audit.write,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "grant_revoked"
    assert audit.events[0].reason == "grant_revoked"


def test_v1_enforce_audit_failure_returns_503_without_decision() -> None:
    def fail_audit(_: AuditEvent) -> None:
        raise RuntimeError("storage unavailable")

    response = enforce_v1_contract(
        request(),
        grants=(grant(),),
        now=NOW,
        write_audit=fail_audit,
    )

    assert response.status_code == 503
    assert response.error == "service_unavailable"
    assert response.decision is None
    assert response.audit_event_id is None


def test_v1_enforce_boundary_denial_writes_audit_event() -> None:
    audit = AuditRecorder()

    response = enforce_v1_contract(
        request(boundary_id="bnd_missing"),
        grants=(grant(),),
        now=NOW,
        write_audit=audit.write,
        boundary_registry=BoundaryRegistry(),
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "boundary_not_found"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].boundary_id == "bnd_missing"
