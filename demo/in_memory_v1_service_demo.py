from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vinctor_core import BoundaryRegistrationInput, BoundaryRegistry, Grant, register_boundary
from vinctor_service import InMemoryV1Service, V1EnforceRequest


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    registry = BoundaryRegistry()
    boundary = register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_demo",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=now,
        boundary_id="bnd_demo",
    )

    service = InMemoryV1Service(
        grants=(
            Grant(
                grant_id="grnt_demo",
                grant_ref="grt_demo",
                workspace_id="ws_demo",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=now + timedelta(hours=1),
            ),
        ),
        boundary_registry=registry,
    )

    permit = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_demo",
            agent_id="agent_release",
            grant_ref="grt_demo",
            action="write",
            resource="repo/feature/readme",
            boundary_id=boundary.boundary_id,
        ),
        now=now,
    )
    assert permit.status_code == 200
    assert permit.decision == "permit"
    assert permit.audit_event_id == service.audit_events[0].event_id

    deny = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_demo",
            agent_id="agent_release",
            grant_ref="grt_demo",
            action="send",
            resource="email/external",
            boundary_id=boundary.boundary_id,
        ),
        now=now,
    )
    assert deny.status_code == 403
    assert deny.error == "action_denied"
    assert deny.audit_event_id == service.audit_events[1].event_id

    missing_grant = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_demo",
            agent_id="agent_release",
            grant_ref="grt_missing",
            action="push",
            resource="repo",
        ),
        now=now,
    )
    assert missing_grant.status_code == 403  # existence oracle: generic 403
    assert missing_grant.decision is None
    assert len(service.audit_events) == 2

    print("ALL IN-MEMORY V1 SERVICE STEPS PASSED \u2713")


if __name__ == "__main__":
    main()
