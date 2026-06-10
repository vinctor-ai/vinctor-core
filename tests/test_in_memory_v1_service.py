from datetime import UTC, datetime, timedelta

from vinctor_core import (
    BoundaryRegistrationInput,
    BoundaryRegistry,
    Grant,
    disable_boundary,
    register_boundary,
)
from vinctor_service import InMemoryV1Service, V1EnforceRequest

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant(
    *,
    grant_id: str = "grnt_main",
    grant_ref: str = "grt_main",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    scopes: tuple[str, ...] = ("write:repo/feature/*",),
    status: str = "active",
) -> Grant:
    return Grant(
        grant_id=grant_id,
        grant_ref=grant_ref,
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=scopes,
        status=status,
        expires_at=NOW + timedelta(hours=1),
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


def test_in_memory_v1_service_permits_and_records_audit_event() -> None:
    service = InMemoryV1Service(grants=(grant(),))

    response = service.enforce(request(), now=NOW)

    assert response.status_code == 200
    assert response.decision == "permit"
    assert response.audit_event_id == service.audit_events[0].event_id
    assert service.audit_events[0].decision == "permit"


def test_in_memory_v1_service_preserves_pre_audit_failures() -> None:
    service = InMemoryV1Service(grants=(grant(),))

    response = service.enforce(
        request(grant_ref="grt_missing", action="push", resource="repo"),
        now=NOW,
    )

    assert response.status_code == 404
    assert response.error == "grant_not_found"
    assert service.audit_events == ()


def test_in_memory_v1_service_records_denies_in_audit_order() -> None:
    service = InMemoryV1Service(grants=(grant(),))

    permit = service.enforce(request(), now=NOW)
    deny = service.enforce(
        request(action="send", resource="email/external"),
        now=NOW,
    )

    assert permit.status_code == 200
    assert deny.status_code == 403
    assert deny.error == "action_denied"
    assert [event.event_id for event in service.audit_events] == [
        permit.audit_event_id,
        deny.audit_event_id,
    ]


def test_in_memory_v1_service_uses_boundary_registry() -> None:
    registry = BoundaryRegistry()
    boundary = register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_valid",
    )
    service = InMemoryV1Service(grants=(grant(),), boundary_registry=registry)

    response = service.enforce(request(boundary_id=boundary.boundary_id), now=NOW)

    assert response.status_code == 200
    assert service.audit_events[0].boundary_id == "bnd_valid"
    assert service.audit_events[0].runtime == "claude-code"
    assert service.audit_events[0].boundary_type == "pretooluse"


def test_in_memory_v1_service_fails_closed_for_disabled_boundary() -> None:
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_disabled",
    )
    disable_boundary(
        registry,
        boundary_id="bnd_disabled",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
    )
    service = InMemoryV1Service(grants=(grant(),), boundary_registry=registry)

    response = service.enforce(request(boundary_id="bnd_disabled"), now=NOW)

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "boundary_inactive"
    assert service.audit_events[0].boundary_id == "bnd_disabled"
    assert service.audit_events[0].runtime == "claude-code"
