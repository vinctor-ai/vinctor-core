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
from vinctor_core.audit import EVENT_AUTH_FAILED, REASON_AUTH_FAILED
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


def test_audit_event_subject_token_verified_defaults_absent_from_to_dict() -> None:
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
        )
    )

    event = build_audit_event(AuditEventInput(decision=decision))

    assert event.subject_token_verified is False
    assert event.token_id is None
    assert "subject_token_verified" not in event.to_dict()
    assert "token_id" not in event.to_dict()


def test_audit_event_records_subject_token_verified_and_token_id() -> None:
    decision = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="execute",
            resource="deploy/staging",
            now=NOW,
        )
    )

    event = build_audit_event(
        AuditEventInput(decision=decision, subject_token_verified=True, token_id="vtk_x")
    )

    assert event.subject_token_verified is True
    assert event.to_dict()["subject_token_verified"] is True
    assert event.to_dict()["token_id"] == "vtk_x"


def test_auth_failure_throttle_emits_timely_event_then_suppresses_window() -> None:
    writer = InMemoryAuditWriter()
    throttle = AuthFailureAuditThrottle(window_seconds=60)

    throttle.record(writer, surface="enforce", now=NOW)
    throttle.record(writer, surface="enforce", now=NOW + timedelta(seconds=30))

    # First failure emits a timely count=1 event immediately; the in-window
    # repeat is counted in memory but emits nothing (no audit-store flood).
    assert [e.event_type for e in writer.events] == [EVENT_AUTH_FAILED]
    timely = writer.events[0]
    assert timely.reason_code == REASON_AUTH_FAILED
    assert timely.reason == REASON_AUTH_FAILED
    assert timely.occurrence_count == 1
    assert timely.first_seen_at == NOW
    assert timely.last_seen_at == NOW
    # Discloses nothing: no resolvable principal, no grant.
    assert timely.workspace_id == ""
    assert timely.agent_id == ""
    assert timely.grant_ref == ""

    # A different surface is tracked independently (its own timely event).
    throttle.record(writer, surface="delegated", now=NOW)
    assert [e.event_type for e in writer.events] == [EVENT_AUTH_FAILED, EVENT_AUTH_FAILED]
    assert writer.events[1].action == "delegated"


def test_auth_failure_throttle_is_bounded_by_surface_not_request_input() -> None:
    # A pre-auth probe hammering one surface (previously able to vary the
    # untrusted x-vinctor-boundary-id header per request, minting one throttle
    # window and one timely audit row per distinct value) must not be able to
    # grow the window map or the audit store: the throttle keys on the trusted
    # surface alone.
    writer = InMemoryAuditWriter()
    throttle = AuthFailureAuditThrottle(window_seconds=60)

    for i in range(1000):
        throttle.record(writer, surface="enforce", now=NOW + timedelta(seconds=i % 30))

    # Bounded cardinality: exactly one window for the surface, any probe volume.
    assert len(throttle._windows) == 1
    # Bounded emissions: a single timely event for the window (no flood).
    assert [e.event_type for e in writer.events] == [EVENT_AUTH_FAILED]
    # No attacker-controlled boundary is attributed into the audit trail.
    assert writer.events[0].boundary_id is None


def test_auth_failure_throttle_aggregates_window_into_summary_on_roll() -> None:
    writer = InMemoryAuditWriter()
    throttle = AuthFailureAuditThrottle(window_seconds=60)

    # Three failures inside one window: a timely count=1 event, then two
    # in-memory increments (no emit).
    throttle.record(writer, surface="enforce", now=NOW)
    throttle.record(writer, surface="enforce", now=NOW + timedelta(seconds=20))
    throttle.record(writer, surface="enforce", now=NOW + timedelta(seconds=40))
    assert len(writer.events) == 1
    assert writer.events[0].occurrence_count == 1

    # A failure after the window rolls: first a summary for the just-closed
    # window (occurrence_count=3 spanning its first/last seen), then the timely
    # first event of the freshly opened window.
    throttle.record(writer, surface="enforce", now=NOW + timedelta(seconds=61))
    assert len(writer.events) == 3

    summary = writer.events[1]
    assert summary.event_type == EVENT_AUTH_FAILED
    assert summary.reason_code == REASON_AUTH_FAILED
    assert summary.occurrence_count == 3
    assert summary.first_seen_at == NOW
    assert summary.last_seen_at == NOW + timedelta(seconds=40)

    new_window_timely = writer.events[2]
    assert new_window_timely.occurrence_count == 1
    assert new_window_timely.first_seen_at == NOW + timedelta(seconds=61)
    assert new_window_timely.last_seen_at == NOW + timedelta(seconds=61)


def test_auth_failure_throttle_window_roll_without_repeats_emits_no_summary() -> None:
    writer = InMemoryAuditWriter()
    throttle = AuthFailureAuditThrottle(window_seconds=60)

    # A single failure per window: each window only ever emits its timely
    # count=1 event; a roll with no in-window repeats emits no summary.
    throttle.record(writer, surface="enforce", now=NOW)
    throttle.record(writer, surface="enforce", now=NOW + timedelta(seconds=61))

    assert len(writer.events) == 2
    assert [e.occurrence_count for e in writer.events] == [1, 1]
    assert writer.events[1].first_seen_at == NOW + timedelta(seconds=61)
