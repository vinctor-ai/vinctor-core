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

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def test_audit_event_to_dict_is_json_safe() -> None:
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
        boundary_id="bnd_valid",
    )
    decision = evaluate_enforce(
        EnforceInput(
            grant=Grant(
                grant_id="grnt_main",
                grant_ref="grt_main",
                workspace_id="ws_main",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=NOW + timedelta(hours=1),
            ),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
            boundary_id="bnd_valid",
            boundary_registry=registry,
        )
    )
    event = build_audit_event(
        AuditEventInput(decision=decision, event_id="evt_valid", created_at=NOW)
    )

    assert event.to_dict() == {
        "event_id": "evt_valid",
        "event_type": "action_permitted",
        "decision": "permit",
        "reason": "permitted",
        "workspace_id": "ws_main",
        "agent_id": "agent_release",
        "grant_id": "grnt_main",
        "grant_ref": "grt_main",
        "action": "write",
        "resource": "repo/feature/readme",
        "scope_attempted": "write:repo/feature/readme",
        "scope_matched": "write:repo/feature/*",
        "boundary_id": "bnd_valid",
        "runtime": "claude-code",
        "boundary_type": "pretooluse",
        "created_at": "2026-06-10T12:00:00+00:00",
    }
