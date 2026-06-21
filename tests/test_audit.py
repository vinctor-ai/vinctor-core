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
from vinctor_service.audit import AuthFailureAuditThrottle, InMemoryAuditWriter

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def active_grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("execute:deploy/staging",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def test_audit_event_includes_valid_boundary_context() -> None:
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="hermes-local",
            runtime="hermes",
            boundary_type="adapter",
        ),
        now=NOW,
        boundary_id="bnd_valid",
    )
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
            boundary_id="bnd_valid",
            boundary_registry=registry,
        )
    )

    event = build_audit_event(
        AuditEventInput(decision=decision, event_id="evt_valid", created_at=NOW)
    )

    assert event.event_type == "action_permitted"
    assert event.boundary_id == "bnd_valid"
    assert event.runtime == "hermes"
    assert event.boundary_type == "adapter"
    assert event.scope_matched == "execute:deploy/staging"


def test_audit_event_for_invalid_boundary_includes_attempted_boundary_id_only() -> None:
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
            boundary_id="bnd_missing",
            boundary_registry=BoundaryRegistry(),
        )
    )

    event = build_audit_event(
        AuditEventInput(decision=decision, event_id="evt_missing", created_at=NOW)
    )

    assert event.event_type == "action_denied"
    assert event.decision == "deny"
    assert event.reason == "boundary_not_found"
    assert event.boundary_id == "bnd_missing"
    assert event.runtime is None
    assert event.boundary_type is None


def test_audit_event_for_disabled_boundary_includes_resolved_boundary_context() -> None:
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="codex-local",
            runtime="codex",
            boundary_type="wrapper",
            status="disabled",
        ),
        now=NOW,
        boundary_id="bnd_disabled",
    )
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
            boundary_id="bnd_disabled",
            boundary_registry=registry,
        )
    )

    event = build_audit_event(
        AuditEventInput(decision=decision, event_id="evt_disabled", created_at=NOW)
    )

    assert event.decision == "deny"
    assert event.reason == "boundary_inactive"
    assert event.boundary_id == "bnd_disabled"
    assert event.runtime == "codex"
    assert event.boundary_type == "wrapper"


def test_audit_event_for_wrong_workspace_boundary_does_not_leak_boundary_context() -> None:
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_other",
            name="langgraph-local",
            runtime="langgraph",
            boundary_type="middleware",
        ),
        now=NOW,
        boundary_id="bnd_other",
    )
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
            boundary_id="bnd_other",
            boundary_registry=registry,
        )
    )

    event = build_audit_event(
        AuditEventInput(decision=decision, event_id="evt_wrong_workspace", created_at=NOW)
    )

    assert event.decision == "deny"
    assert event.reason == "boundary_wrong_workspace"
    assert event.boundary_id == "bnd_other"
    assert event.runtime is None
    assert event.boundary_type is None


def test_audit_event_has_no_raw_tool_or_prompt_fields() -> None:
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
        )
    )

    event = build_audit_event(AuditEventInput(decision=decision))

    assert not hasattr(event, "raw_tool_input")
    assert not hasattr(event, "raw_command")
    assert not hasattr(event, "prompt")
    assert not hasattr(event, "model_reason")


def test_audit_event_preserves_scope_validation_reason() -> None:
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="publish",
            resource="deploy/staging",
            now=NOW,
        )
    )

    event = build_audit_event(
        AuditEventInput(decision=decision, event_id="evt_invalid_action", created_at=NOW)
    )

    assert event.decision == "deny"
    assert event.reason == "invalid_action"
    assert event.action == "publish"
    assert event.resource == "deploy/staging"
    assert event.scope_attempted == "publish:deploy/staging"
    assert event.scope_matched is None


def test_audit_event_enforcing_principal_defaults_to_none() -> None:
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
        )
    )

    event = build_audit_event(AuditEventInput(decision=decision))

    # Direct /v1/enforce: the agent enforces for itself, no separate principal.
    assert event.enforcing_principal is None
    assert "enforcing_principal" not in event.to_dict()


def test_audit_event_records_enforcing_principal_when_set() -> None:
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
        )
    )

    event = build_audit_event(
        AuditEventInput(decision=decision, enforcing_principal="pep_git_host")
    )

    # Delegated path: the PEP principal is recorded separately from the subject.
    assert event.enforcing_principal == "pep_git_host"
    assert event.agent_id == "agent_release"
    assert event.to_dict()["enforcing_principal"] == "pep_git_host"


def test_auth_failure_throttle_rate_limits_within_window() -> None:
    writer = InMemoryAuditWriter()
    throttle = AuthFailureAuditThrottle(window_seconds=60)

    throttle.record(writer, surface="enforce", boundary_id=None, now=NOW)
    throttle.record(writer, surface="enforce", boundary_id=None, now=NOW + timedelta(seconds=30))

    # Within the window the repeat probe is suppressed (no audit-store flood).
    assert [e.event_type for e in writer.events] == ["auth_failed"]
    assert writer.events[0].reason == "auth_failed"
    # Discloses nothing: no resolvable principal, no grant.
    assert writer.events[0].workspace_id == ""
    assert writer.events[0].agent_id == ""
    assert writer.events[0].grant_ref == ""

    # After the window, a fresh event is recorded.
    throttle.record(writer, surface="enforce", boundary_id=None, now=NOW + timedelta(seconds=61))
    assert len(writer.events) == 2

    # A different surface is tracked independently.
    throttle.record(writer, surface="delegated", boundary_id=None, now=NOW)
    assert len(writer.events) == 3
