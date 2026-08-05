from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vinctor_core import (
    AuditEventInput,
    BoundaryRegistrationInput,
    BoundaryRegistry,
    EnforceInput,
    Grant,
    build_audit_event,
    evaluate_enforce,
    register_boundary,
)


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

    grant = Grant(
        grant_id="grnt_demo",
        grant_ref="grt_demo",
        workspace_id="ws_demo",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=now + timedelta(hours=1),
    )

    permit = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action="write",
            resource="repo/feature/readme",
            now=now,
            boundary_id=boundary.boundary_id,
            boundary_registry=registry,
        )
    )
    assert permit.decision == "permit"
    assert permit.reason == "permitted"

    permit_event = build_audit_event(
        AuditEventInput(decision=permit, event_id="evt_permit", created_at=now)
    )
    assert permit_event.boundary_id == "bnd_demo"
    assert permit_event.runtime == "claude-code"
    assert permit_event.boundary_type == "pretooluse"

    deny = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action="send",
            resource="email/external",
            now=now,
            boundary_id=boundary.boundary_id,
            boundary_registry=registry,
        )
    )
    assert deny.decision == "deny"
    assert deny.reason == "action_denied"

    missing_boundary = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action="write",
            resource="repo/feature/readme",
            now=now,
            boundary_id="bnd_missing",
            boundary_registry=registry,
        )
    )
    assert missing_boundary.decision == "deny"
    assert missing_boundary.reason == "boundary_not_found"

    missing_boundary_event = build_audit_event(
        AuditEventInput(decision=missing_boundary, event_id="evt_missing", created_at=now)
    )
    assert missing_boundary_event.boundary_id == "bnd_missing"
    assert missing_boundary_event.runtime is None
    assert missing_boundary_event.boundary_type is None

    print("ALL BOUNDARY REGISTRY CORE E2E STEPS PASSED \u2713")


if __name__ == "__main__":
    main()
