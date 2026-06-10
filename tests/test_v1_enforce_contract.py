from datetime import UTC, datetime, timedelta

from vinctor_core import (
    BoundaryRegistry,
    Grant,
)
from vinctor_core.audit import AuditEvent
from vinctor_service import (
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    V1EnforceRequest,
    enforce_v1_contract,
)

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


class FailingGrantRepository:
    def get_by_ref(self, grant_ref: str) -> Grant | None:
        raise RuntimeError(f"lookup failed for {grant_ref}")


class FailingAuditWriter:
    def write(self, event: AuditEvent) -> None:
        raise RuntimeError(f"storage unavailable for {event.event_id}")


def repository(*grants: Grant) -> InMemoryGrantRepository:
    return InMemoryGrantRepository(grants)


def test_v1_enforce_permit_writes_audit_before_returning_decision() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].decision == "permit"
    assert audit.events[0].scope_matched == "write:repo/feature/*"


def test_v1_enforce_scope_deny_writes_audit_event() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "action_denied"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].reason == "action_denied"


def test_v1_enforce_grant_not_found_returns_404_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 404
    assert response.error == "grant_not_found"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_grant_lookup_failure_returns_503_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(),
        grant_repository=FailingGrantRepository(),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 503
    assert response.error == "service_unavailable"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_missing_grant_precedes_invalid_request_validation() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(grant_ref="grt_missing", action="push", resource="repo"),
        grant_repository=repository(),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 404
    assert response.error == "grant_not_found"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_cross_agent_misuse_returns_forbidden_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_wrong_workspace_returns_forbidden_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(workspace_id="ws_other"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_invalid_action_maps_to_scope_invalid_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(action="push", resource="repo/main"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 400
    assert response.error == "scope_invalid"
    assert "push" in response.reason
    assert "write" in response.reason
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_invalid_resource_maps_to_scope_invalid_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(resource="repo"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 400
    assert response.error == "scope_invalid"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_revoked_grant_writes_deny_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(),
        grant_repository=repository(grant(status="revoked")),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "grant_revoked"
    assert audit.events[0].reason == "grant_revoked"


def test_v1_enforce_audit_failure_returns_503_without_decision() -> None:
    response = enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=FailingAuditWriter(),
    )

    assert response.status_code == 503
    assert response.error == "service_unavailable"
    assert response.decision is None
    assert response.audit_event_id is None


def test_v1_enforce_boundary_denial_writes_audit_event() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(boundary_id="bnd_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        boundary_registry=BoundaryRegistry(),
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "boundary_not_found"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].boundary_id == "bnd_missing"


def test_in_memory_audit_writer_records_events_in_order() -> None:
    audit = InMemoryAuditWriter()

    first = enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )
    second = enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert [event.event_id for event in audit.events] == [
        first.audit_event_id,
        second.audit_event_id,
    ]


def test_in_memory_grant_repository_rejects_duplicate_grant_refs() -> None:
    duplicate = grant(grant_id="grnt_duplicate")

    try:
        InMemoryGrantRepository((grant(), duplicate))
    except ValueError as error:
        assert "duplicate grant_ref" in str(error)
    else:
        raise AssertionError("expected duplicate grant_ref to be rejected")
