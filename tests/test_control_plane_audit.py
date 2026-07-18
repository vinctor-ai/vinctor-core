"""PKA-44 / ADR 0019: control-plane mutations are audited on the decision chain.

Control events share the ONE hash chain with decision events, distinguished by
``event_class`` (``control`` / ``decision``); the ordering between a rule change
and an action IS the evidence. Every control mutation and its audit event commit
as one unit, and no control repo can be constructed without an audit path.
"""
from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime

from vinctor_core.models import AuditEvent, BoundaryRegistrationInput
from vinctor_service.models import AutoApprovalRule

NOW = datetime(2026, 7, 18, 12, 0, tzinfo=UTC)


def _decision_event(event_id: str = "evt_1") -> AuditEvent:
    return AuditEvent(
        event_id=event_id, event_type="action_permitted", decision="permit",
        reason="ok", workspace_id="ws_main", agent_id="agent_a", grant_id="grnt_1",
        grant_ref="grt_1", action="read", resource="repo/x",
        scope_attempted="read:repo/x", scope_matched="read:repo/*",
        boundary_id="bnd_1", runtime="claude-code", boundary_type="pretooluse",
        created_at=NOW,
    )


# --- event_class on the model / canonical JSON -----------------------------


def test_audit_event_defaults_to_decision_class() -> None:
    assert _decision_event().event_class == "decision"


def test_decision_events_omit_event_class_from_canonical_json() -> None:
    # Decision-event canonical JSON stays byte-identical to the pre-PKA-44
    # format: absent key == "decision", for old and new rows uniformly (same
    # omit-when-default convention as subject_token_verified).
    assert "event_class" not in _decision_event().to_dict()


def test_control_events_carry_event_class_in_canonical_json() -> None:
    event = replace(_decision_event(), event_class="control")
    assert event.to_dict()["event_class"] == "control"


def test_sqlite_json_reader_defaults_absent_event_class_to_decision() -> None:
    import json

    from vinctor_service.sqlite import _audit_event_from_json

    data = _decision_event().to_dict()
    assert "event_class" not in data
    restored = _audit_event_from_json(json.dumps(data, sort_keys=True))
    assert restored.event_class == "decision"


def test_sqlite_json_reader_round_trips_control_class() -> None:
    import json

    from vinctor_service.sqlite import _audit_event_from_json

    event = replace(_decision_event(), event_class="control")
    restored = _audit_event_from_json(json.dumps(event.to_dict(), sort_keys=True))
    assert restored.event_class == "control"


def test_postgres_json_reader_defaults_and_round_trips_event_class() -> None:
    import json

    from vinctor_service.postgres import _audit_event_from_json

    plain = _audit_event_from_json(
        json.dumps(_decision_event().to_dict(), sort_keys=True)
    )
    assert plain.event_class == "decision"
    control = _audit_event_from_json(
        json.dumps(replace(_decision_event(), event_class="control").to_dict(),
                   sort_keys=True)
    )
    assert control.event_class == "control"


# --- control event builder -------------------------------------------------


def _build_control(**overrides):
    from vinctor_core.audit import build_control_audit_event

    kwargs = dict(
        event_type="enforcement_setting_changed",
        workspace_id="ws_main",
        action="set_require_boundary",
        resource="enforcement_setting/require_boundary",
        reason="require_boundary=true",
        created_at=NOW,
    )
    kwargs.update(overrides)
    return build_control_audit_event(**kwargs)


def test_control_event_builder_field_contract() -> None:
    event = _build_control()
    assert event.event_class == "control"
    assert event.decision == "permit"
    assert event.event_type == "enforcement_setting_changed"
    # No grant is involved and nothing agent-facing: empty grant identifiers,
    # no boundary attribution, no coarse reason_code (the agent-facing deny
    # surface must not widen).
    assert event.grant_id == "" and event.grant_ref == ""
    assert event.boundary_id is None and event.reason_code is None
    assert event.workspace_id == "ws_main"
    assert event.action == "set_require_boundary"
    assert event.resource == "enforcement_setting/require_boundary"
    assert event.created_at == NOW
    assert event.event_id.startswith("evt_")


def test_control_event_builder_carries_target_agent_and_principal() -> None:
    event = _build_control(agent_id="agent_a", enforcing_principal="usr_owner")
    assert event.agent_id == "agent_a"
    assert event.enforcing_principal == "usr_owner"


# --- ControlPlaneAuditor ---------------------------------------------------


def _auditor():
    from vinctor_service.audit import InMemoryAuditWriter
    from vinctor_service.control_audit import ControlPlaneAuditor

    writer = InMemoryAuditWriter()
    return ControlPlaneAuditor(writer), writer


def _record(auditor, reason: str = "require_boundary=true") -> None:
    auditor.record(
        event_type="enforcement_setting_changed",
        workspace_id="ws_main",
        action="set_require_boundary",
        resource="enforcement_setting/require_boundary",
        reason=reason,
        now=NOW,
    )


def test_auditor_record_writes_one_control_event() -> None:
    auditor, writer = _auditor()
    _record(auditor)
    assert len(writer.events) == 1
    assert writer.events[0].event_class == "control"


def test_composite_suppresses_inner_records_and_writes_exactly_one() -> None:
    # Policy apply drives the audited bounds/settings repos internally; the
    # operation must emit exactly ONE control event, not one per inner write.
    auditor, writer = _auditor()
    with auditor.composite() as pending:
        _record(auditor)  # inner repo-level record: suppressed
        _record(auditor)
        pending.set(
            event_type="policy_applied",
            workspace_id="ws_main",
            action="policy_apply",
            resource="policy/version/1",
            reason="bounds_set=1 rules_created=0 rules_updated=0",
            now=NOW,
        )
    assert [e.event_type for e in writer.events] == ["policy_applied"]


def test_composite_without_recorded_event_raises_and_writes_nothing() -> None:
    # Fail closed: a composite control operation that finishes without its
    # audit event must raise (unwinding the enclosing transaction) rather than
    # silently committing an un-audited rule change.
    import pytest

    auditor, writer = _auditor()
    with pytest.raises(RuntimeError, match="without recording"), auditor.composite():
        _record(auditor)
    assert writer.events == []


def test_composite_body_exception_writes_nothing() -> None:
    import pytest

    auditor, writer = _auditor()
    with pytest.raises(ValueError, match="boom"), auditor.composite() as pending:
        pending.set(
            event_type="policy_applied", workspace_id="ws_main",
            action="policy_apply", resource="policy/version/1",
            reason="", now=NOW,
        )
        raise ValueError("boom")
    assert writer.events == []


def test_composite_restores_recording_after_exit() -> None:
    auditor, writer = _auditor()
    with auditor.composite() as pending:
        pending.set(
            event_type="policy_applied", workspace_id="ws_main",
            action="policy_apply", resource="policy/version/1",
            reason="", now=NOW,
        )
    _record(auditor)
    assert [e.event_type for e in writer.events] == [
        "policy_applied", "enforcement_setting_changed",
    ]


def test_composite_set_twice_raises() -> None:
    import pytest

    auditor, writer = _auditor()
    with pytest.raises(RuntimeError, match="already recorded"), auditor.composite() as pending:
        pending.set(
            event_type="policy_applied", workspace_id="ws_main",
            action="policy_apply", resource="policy/version/1",
            reason="", now=NOW,
        )
        pending.set(
            event_type="policy_applied", workspace_id="ws_main",
            action="policy_apply", resource="policy/version/2",
            reason="", now=NOW,
        )


# --- SQLite control repos: audited + atomic --------------------------------


def _sqlite_service():
    from vinctor_service.sqlite import SQLiteV1Service
    from vinctor_service.sqlite_txn import connect_sqlite

    return SQLiteV1Service(connect_sqlite(":memory:"))


def _control_events(service):
    return [e for e in service.audit_writer.list_all() if e.event_class == "control"]


def _break_audit(service) -> None:
    def _raise(*_args, **_kwargs):
        raise RuntimeError("audit write failed")

    service.audit_writer.write = _raise  # type: ignore[method-assign]


def _auto_approval_rule(*, status: str = "active") -> AutoApprovalRule:
    return AutoApprovalRule(
        rule_id="apr_release",
        workspace_id="ws_main",
        name="release",
        target_agent_id="agent_release",
        allowed_scopes=("execute:deploy/env/*",),
        max_ttl_seconds=1800,
        status=status,
        created_by="operator:a",
        created_at=NOW,
    )


def test_sqlite_boundary_and_rule_mutations_emit_one_control_event_each() -> None:
    import json

    service = _sqlite_service()
    service.register_boundary(
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        boundary_id="bnd_main",
        now=NOW,
    )
    service.disable_boundary(
        boundary_id="bnd_main", workspace_id="ws_main", now=NOW
    )
    service.enable_boundary(
        boundary_id="bnd_main", workspace_id="ws_main", now=NOW
    )
    service.create_auto_approval_rule(_auto_approval_rule())
    service.disable_auto_approval_rule(
        rule_id="apr_release",
        workspace_id="ws_main",
        disabled_by="operator:b",
        now=NOW,
    )

    events = _control_events(service)
    assert [
        (event.event_type, event.action, event.resource, event.reason)
        for event in events
    ] == [
        (
            "boundary_registered",
            "register_boundary",
            "boundary/bnd_main",
            "status=active",
        ),
        (
            "boundary_status_changed",
            "disable_boundary",
            "boundary/bnd_main",
            "status=disabled",
        ),
        (
            "boundary_status_changed",
            "enable_boundary",
            "boundary/bnd_main",
            "status=active",
        ),
        (
            "auto_approval_rule_created",
            "create_auto_approval_rule",
            "auto_approval_rule/apr_release",
            "status=active",
        ),
        (
            "auto_approval_rule_disabled",
            "disable_auto_approval_rule",
            "auto_approval_rule/apr_release",
            "status=disabled",
        ),
    ]
    assert all(event.event_class == "control" for event in events)
    assert events[0].boundary_id == "bnd_main"
    assert all(event.workspace_id == "ws_main" for event in events)
    assert all(event.agent_id == "" and event.scope_attempted == "" for event in events)
    assert events[0].runtime is None and events[0].boundary_type is None
    serialized = json.dumps([event.to_dict() for event in events])
    assert "fail_closed" not in serialized
    assert "execute:deploy/*" not in serialized
    assert "agent_release" not in serialized
    assert service.audit_writer.verify_chain().ok is True


def test_sqlite_boundary_mutation_rolls_back_when_audit_write_fails() -> None:
    import pytest

    service = _sqlite_service()
    service.register_boundary(
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        boundary_id="bnd_main",
        now=NOW,
    )
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        service.disable_boundary(
            boundary_id="bnd_main", workspace_id="ws_main", now=NOW
        )

    boundary = service.get_boundary(
        boundary_id="bnd_main", workspace_id="ws_main"
    )
    assert boundary is not None and boundary.status == "active"


def test_sqlite_rule_create_rolls_back_when_audit_write_fails() -> None:
    import pytest

    service = _sqlite_service()
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        service.create_auto_approval_rule(_auto_approval_rule())

    assert service.list_auto_approval_rules(workspace_id="ws_main") == ()


def test_sqlite_rule_disable_rolls_back_when_audit_write_fails() -> None:
    import pytest

    service = _sqlite_service()
    service.create_auto_approval_rule(_auto_approval_rule())
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        service.disable_auto_approval_rule(
            rule_id="apr_release",
            workspace_id="ws_main",
            disabled_by="operator:b",
            now=NOW,
        )

    rules = service.list_auto_approval_rules(workspace_id="ws_main")
    assert len(rules) == 1 and rules[0].status == "active"


def test_sqlite_rule_direct_update_emits_update_control_event() -> None:
    # PKA-56 B1: a direct update that widens scopes / changes TTL / re-enables
    # must emit its own control event, not silently commit un-audited.
    service = _sqlite_service()
    service.create_auto_approval_rule(_auto_approval_rule())
    repo = service.auto_approval_rule_repository
    prior = repo.get_rule("apr_release")
    assert prior is not None
    widened = replace(
        prior,
        allowed_scopes=("execute:deploy/prod/*", "execute:rollback/prod/*"),
        max_ttl_seconds=7200,
        updated_by="operator:c",
        updated_at=NOW,
    )
    repo.update_rule(widened)

    events = _control_events(service)
    assert [e.event_type for e in events] == [
        "auto_approval_rule_created",
        "auto_approval_rule_updated",
    ]
    update = events[1]
    assert update.action == "update_auto_approval_rule"
    assert update.resource == "auto_approval_rule/apr_release"
    assert update.reason == "status=active changed=allowed_scopes,max_ttl_seconds"
    assert update.scope_attempted == ""
    assert update.enforcing_principal == "operator:c"
    serialized = json.dumps(update.to_dict())
    assert "execute:deploy/prod/*" not in serialized
    assert "agent_release" not in serialized
    assert service.audit_writer.verify_chain().ok is True


def test_sqlite_rule_reenable_emits_update_control_event() -> None:
    from dataclasses import replace

    service = _sqlite_service()
    service.create_auto_approval_rule(_auto_approval_rule())
    service.disable_auto_approval_rule(
        rule_id="apr_release", workspace_id="ws_main",
        disabled_by="operator:b", now=NOW,
    )
    repo = service.auto_approval_rule_repository
    disabled = repo.get_rule("apr_release")
    assert disabled is not None and disabled.status == "disabled"
    reenabled = replace(disabled, status="active", updated_by="operator:d", updated_at=NOW)
    repo.update_rule(reenabled)

    events = _control_events(service)
    assert [e.event_type for e in events] == [
        "auto_approval_rule_created",
        "auto_approval_rule_disabled",
        "auto_approval_rule_updated",
    ]
    assert events[2].reason == "status=active changed=status"
    assert events[2].enforcing_principal == "operator:d"


def test_sqlite_rule_direct_update_rolls_back_when_audit_write_fails() -> None:
    from dataclasses import replace

    import pytest

    service = _sqlite_service()
    service.create_auto_approval_rule(_auto_approval_rule())
    repo = service.auto_approval_rule_repository
    prior = repo.get_rule("apr_release")
    assert prior is not None
    _break_audit(service)
    widened = replace(
        prior,
        allowed_scopes=("execute:deploy/prod/*", "execute:rollback/prod/*"),
    )

    with pytest.raises(RuntimeError, match="audit write failed"):
        repo.update_rule(widened)

    # The widen unwound with its failed audit write.
    assert repo.get_rule("apr_release").allowed_scopes == ("execute:deploy/env/*",)


def test_sqlite_control_events_carry_enforcing_principal(tmp_path) -> None:
    # PKA-56 B4: WHO changed the rules must be attributable on the control
    # events, not just on policy apply/rollback.
    service = _sqlite_service()
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws_main", agent_id="agent_a", require_boundary=True, now=NOW,
        enforcing_principal="workspace:ws_main",
    )
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main", agent_id="agent_a",
        scopes=("read:repo/project/*",), now=NOW,
        enforcing_principal="workspace:ws_main",
    )
    service.register_boundary(
        BoundaryRegistrationInput(
            workspace_id="ws_main", name="claude-code",
            runtime="claude-code", boundary_type="pretooluse",
        ),
        boundary_id="bnd_main", now=NOW,
        enforcing_principal="workspace:ws_main",
    )
    service.disable_boundary(
        boundary_id="bnd_main", workspace_id="ws_main", now=NOW,
        enforcing_principal="workspace:ws_main",
    )
    events = _control_events(service)
    assert [e.action for e in events] == [
        "set_require_boundary",
        "set_issuable_scope_bounds",
        "register_boundary",
        "disable_boundary",
    ]
    assert all(e.enforcing_principal == "workspace:ws_main" for e in events)
    assert service.audit_writer.verify_chain().ok is True


def test_boundary_http_attributes_enforcing_principal() -> None:
    # The authenticated workspace identity flows to the control event as a
    # stable, non-secret principal id.
    from vinctor_service.boundary_http import (
        WorkspaceIdentity,
        handle_v1_boundaries_http,
    )

    service = _sqlite_service()
    key = "wsk_test"
    identities = {key: WorkspaceIdentity(workspace_id="ws_main")}
    response = handle_v1_boundaries_http(
        method="POST",
        path="/v1/boundaries",
        headers={"X-Workspace-Key": key},
        body={
            "name": "claude-code",
            "runtime": "claude-code",
            "boundary_type": "pretooluse",
            "mode": "fail_closed",
        },
        workspace_identities=identities,
        service=service,
        now=NOW,
    )
    assert response.status_code == 201
    events = _control_events(service)
    assert len(events) == 1
    assert events[0].event_type == "boundary_registered"
    assert events[0].enforcing_principal == "workspace:ws_main"


def test_sqlite_set_require_boundary_emits_one_control_event() -> None:
    service = _sqlite_service()
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws_main", agent_id="", require_boundary=True, now=NOW
    )
    events = _control_events(service)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "enforcement_setting_changed"
    assert event.action == "set_require_boundary"
    assert event.resource == "enforcement_setting/require_boundary"
    assert event.reason == "require_boundary=true"
    assert event.workspace_id == "ws_main" and event.agent_id == ""


def test_sqlite_each_mandate_toggle_emits_one_control_event() -> None:
    service = _sqlite_service()
    repo = service.agent_enforcement_settings_repository
    repo.set_require_boundary(
        workspace_id="ws_main", agent_id="agent_a", require_boundary=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_a", require_subject_token=True, now=NOW
    )
    repo.set_require_pop(
        workspace_id="ws_main", agent_id="agent_a", require_pop=False, now=NOW
    )
    events = _control_events(service)
    assert [(e.action, e.reason, e.agent_id) for e in events] == [
        ("set_require_boundary", "require_boundary=true", "agent_a"),
        ("set_require_subject_token", "require_subject_token=true", "agent_a"),
        ("set_require_pop", "require_pop=false", "agent_a"),
    ]
    assert all(e.event_type == "enforcement_setting_changed" for e in events)


def test_sqlite_set_bounds_emits_one_control_event_with_scopes() -> None:
    service = _sqlite_service()
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main", agent_id="agent_a",
        scopes=("read:repo/project/*", "execute:ci/test"),
        max_ttl_seconds=3600,
        now=NOW,
    )
    events = _control_events(service)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "scope_bounds_set"
    assert event.action == "set_issuable_scope_bounds"
    assert event.resource == "issuable_scope_bounds/agent_a"
    assert event.agent_id == "agent_a"
    # The new bounds ARE the evidence (a widened grant surface must be visible
    # to the operator), so they ride in scope_attempted.
    assert event.scope_attempted == "read:repo/project/* execute:ci/test"
    assert event.reason == "max_ttl_seconds=3600"


def test_sqlite_mandate_toggle_rolls_back_when_audit_write_fails() -> None:
    import pytest

    service = _sqlite_service()
    _break_audit(service)
    repo = service.agent_enforcement_settings_repository
    with pytest.raises(RuntimeError, match="audit write failed"):
        repo.set_require_boundary(
            workspace_id="ws_main", agent_id="agent_a", require_boundary=True, now=NOW
        )
    # A rule change that lands without its audit row would be worse than an
    # un-audited one: the toggle must have unwound with the failed audit write.
    assert repo.get_require_boundary_setting(
        workspace_id="ws_main", agent_id="agent_a"
    ) is None


def test_sqlite_set_bounds_rolls_back_when_audit_write_fails() -> None:
    import pytest

    service = _sqlite_service()
    _break_audit(service)
    with pytest.raises(RuntimeError, match="audit write failed"):
        service.set_agent_issuable_scope_bounds(
            workspace_id="ws_main", agent_id="agent_a",
            scopes=("read:repo/project/*",), now=NOW,
        )
    assert service.scope_bounds_repository.get_bounds(
        workspace_id="ws_main", agent_id="agent_a"
    ) is None


def test_sqlite_control_repos_cannot_be_built_without_an_auditor(tmp_path) -> None:
    # No silent un-audited path: dropping the audit writer from a control repo
    # is a construction-time failure, not a quietly unrecorded mutation.
    import pytest

    from vinctor_service.sqlite import (
        SQLiteAgentEnforcementSettingsRepository,
        SQLiteAgentIssuableScopeBoundsRepository,
        SQLiteAutoApprovalRuleRepository,
        SQLiteBoundaryRegistry,
        init_sqlite_schema,
    )
    from vinctor_service.sqlite_txn import connect_sqlite

    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    with pytest.raises(TypeError):
        SQLiteAgentEnforcementSettingsRepository(conn)
    with pytest.raises(TypeError):
        SQLiteAgentIssuableScopeBoundsRepository(conn)
    with pytest.raises(TypeError):
        SQLiteBoundaryRegistry(conn)
    with pytest.raises(TypeError):
        SQLiteAutoApprovalRuleRepository(conn)


# --- policy apply / rollback: exactly ONE control event each ---------------


_POLICY_DOC = """
version: 1
workspace_id: ws_main
agent_bounds:
  - agent_id: agent_a
    scopes: [read:repo/a]
  - agent_id: agent_b
    scopes: [write:repo/b]
auto_approval_rules: []
require_boundary:
  workspace: true
"""


def _apply(service, tmp_path, body: str = _POLICY_DOC, applied_by: str = "operator:a"):
    from vinctor_service.policy_files import apply_policy_file

    path = tmp_path / "policy.yaml"
    path.write_text(body.strip(), encoding="utf-8")
    return apply_policy_file(
        path, service=service, workspace_id="ws_main", applied_by=applied_by, now=NOW
    )


def test_sqlite_policy_apply_emits_exactly_one_control_event(tmp_path) -> None:
    # The apply drives the audited bounds/settings repositories internally
    # (2 bounds + 1 workspace mandate here); the OPERATION is the audited
    # unit — exactly one policy_applied event, with the version snapshot as
    # the detailed record.
    service = _sqlite_service()
    result = _apply(service, tmp_path)

    events = _control_events(service)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "policy_applied"
    assert event.action == "policy_apply"
    assert event.resource == f"policy/version/{result.policy_version}"
    assert event.enforcing_principal == "operator:a"
    assert event.reason == "bounds_set=2 rules_created=0 rules_updated=0"
    # The inner mutations still landed.
    assert service.scope_bounds_repository.get_bounds(
        workspace_id="ws_main", agent_id="agent_a"
    ) == ("read:repo/a",)
    assert service.agent_enforcement_settings_repository.get_require_boundary_setting(
        workspace_id="ws_main", agent_id=""
    ) is True
    assert service.audit_writer.verify_chain().ok is True


def test_sqlite_policy_rollback_emits_exactly_one_control_event(tmp_path) -> None:
    from vinctor_service.policy_files import rollback_policy_version

    service = _sqlite_service()
    first = _apply(service, tmp_path)
    result = rollback_policy_version(
        service=service, workspace_id="ws_main",
        version=first.policy_version, applied_by="operator:b", now=NOW,
    )

    events = _control_events(service)
    assert [e.event_type for e in events] == ["policy_applied", "policy_rolled_back"]
    rollback_event = events[1]
    assert rollback_event.action == "policy_rollback"
    assert rollback_event.resource == f"policy/version/{result.policy_version}"
    assert rollback_event.reason == f"restored_version={first.policy_version}"
    assert rollback_event.enforcing_principal == "operator:b"
    assert service.audit_writer.verify_chain().ok is True


def test_sqlite_policy_apply_rolls_back_whole_apply_when_audit_fails(tmp_path) -> None:
    import pytest

    from vinctor_service.policy_files import list_policy_versions

    service = _sqlite_service()
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        _apply(service, tmp_path)

    # The WHOLE apply unwound with its failed audit event: no bounds, no
    # mandate, no version snapshot.
    assert service.scope_bounds_repository.get_bounds(
        workspace_id="ws_main", agent_id="agent_a"
    ) is None
    assert service.agent_enforcement_settings_repository.get_require_boundary_setting(
        workspace_id="ws_main", agent_id=""
    ) is None
    assert list_policy_versions(service=service, workspace_id="ws_main") == ()


# --- key rotation: one key_rotated event per rotation ----------------------


def _key_service_and_repo():
    from vinctor_service.keys import SQLiteLocalKeyRepository

    service = _sqlite_service()
    return service, SQLiteLocalKeyRepository(service.conn)


def test_sqlite_workspace_key_rotation_emits_one_control_event() -> None:
    from vinctor_service.key_ops import rotate_workspace_key

    service, repo = _key_service_and_repo()
    repo.create_workspace_key(workspace_id="ws_main", now=NOW)
    result = rotate_workspace_key(
        repo, workspace_id="ws_main", now=NOW,
        control_auditor=service.control_auditor,
    )

    events = _control_events(service)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "key_rotated"
    assert event.action == "rotate_workspace_key"
    assert event.resource == f"key/workspace/{result.new_key_id}"
    assert event.reason == "revoked=1"
    assert event.workspace_id == "ws_main" and event.agent_id == ""
    # Safe metadata only: neither the plaintext key nor its hash may reach the
    # audit trail.
    import json

    serialized = json.dumps(events[0].to_dict())
    assert result.raw_key not in serialized
    assert service.audit_writer.verify_chain().ok is True


def test_sqlite_every_rotation_kind_emits_one_control_event() -> None:
    from vinctor_service.key_ops import (
        rotate_agent_key,
        rotate_auditor_key,
        rotate_pep_key,
        rotate_service_operator_key,
    )

    service, repo = _key_service_and_repo()
    auditor = service.control_auditor
    rotate_auditor_key(repo, workspace_id="ws_main", now=NOW, control_auditor=auditor)
    rotate_service_operator_key(repo, now=NOW, control_auditor=auditor)
    rotate_agent_key(
        repo, workspace_id="ws_main", agent_id="agent_a", now=NOW,
        control_auditor=auditor,
    )
    rotate_pep_key(
        repo, workspace_id="ws_main", pep_id="pep_ci", now=NOW,
        control_auditor=auditor,
    )

    events = _control_events(service)
    assert [(e.event_type, e.action, e.workspace_id, e.agent_id) for e in events] == [
        ("key_rotated", "rotate_auditor_key", "ws_main", ""),
        ("key_rotated", "rotate_service_operator_key", "*", ""),
        ("key_rotated", "rotate_agent_key", "ws_main", "agent_a"),
        ("key_rotated", "rotate_pep_key", "ws_main", "pep_ci"),
    ]
    assert service.audit_writer.verify_chain().ok is True


def test_sqlite_rotation_rolls_back_when_audit_write_fails() -> None:
    import pytest

    from vinctor_service.key_ops import rotate_workspace_key

    service, repo = _key_service_and_repo()
    old = repo.create_workspace_key(workspace_id="ws_main", now=NOW)
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        rotate_workspace_key(
            repo, workspace_id="ws_main", now=NOW,
            control_auditor=service.control_auditor,
        )

    # The rotation unwound with its failed audit event: the old key is still
    # the only active one and no new key exists.
    records = repo.list_for_workspace("ws_main")
    active = [r for r in records if r.status == "active"]
    assert [r.key_id for r in active] == [old.record.key_id]


def test_rotation_requires_a_control_auditor() -> None:
    import pytest

    from vinctor_service.key_ops import rotate_workspace_key

    _service, repo = _key_service_and_repo()
    with pytest.raises(TypeError):
        rotate_workspace_key(repo, workspace_id="ws_main", now=NOW)


# --- key revocation: one key_revoked event per revocation (PKA-56 B2) ------


def test_sqlite_key_revoke_emits_one_control_event() -> None:
    from vinctor_service.key_ops import revoke_local_key

    service, repo = _key_service_and_repo()
    created = repo.create_agent_key(workspace_id="ws_main", agent_id="agent_a", now=NOW)

    record = revoke_local_key(
        repo, key_id=created.record.key_id, now=NOW,
        control_auditor=service.control_auditor,
        enforcing_principal="workspace:ws_main",
    )
    assert record is not None and record.status == "revoked"

    events = _control_events(service)
    assert len(events) == 1
    event = events[0]
    assert event.event_type == "key_revoked"
    assert event.action == "revoke_key"
    assert event.resource == f"key/agent/{created.record.key_id}"
    assert event.reason == "status=revoked"
    assert event.workspace_id == "ws_main" and event.agent_id == ""
    assert event.enforcing_principal == "workspace:ws_main"
    import json

    assert created.raw_key not in json.dumps(event.to_dict())
    assert service.audit_writer.verify_chain().ok is True


def test_sqlite_key_revoke_unknown_returns_none_and_emits_nothing() -> None:
    from vinctor_service.key_ops import revoke_local_key

    service, repo = _key_service_and_repo()
    result = revoke_local_key(
        repo, key_id="lkey_missing", now=NOW,
        control_auditor=service.control_auditor,
    )
    assert result is None
    assert _control_events(service) == []


def test_sqlite_key_revoke_already_revoked_is_idempotent_no_event() -> None:
    from vinctor_service.key_ops import revoke_local_key

    service, repo = _key_service_and_repo()
    created = repo.create_agent_key(workspace_id="ws_main", agent_id="agent_a", now=NOW)
    revoke_local_key(
        repo, key_id=created.record.key_id, now=NOW,
        control_auditor=service.control_auditor,
    )
    # A second revoke changes no state and must emit no additional event.
    again = revoke_local_key(
        repo, key_id=created.record.key_id, now=NOW,
        control_auditor=service.control_auditor,
    )
    assert again is not None and again.status == "revoked"
    assert len(_control_events(service)) == 1


def test_sqlite_key_revoke_rolls_back_when_audit_write_fails() -> None:
    import pytest

    from vinctor_service.key_ops import revoke_local_key

    service, repo = _key_service_and_repo()
    created = repo.create_agent_key(workspace_id="ws_main", agent_id="agent_a", now=NOW)
    _break_audit(service)

    with pytest.raises(RuntimeError, match="audit write failed"):
        revoke_local_key(
            repo, key_id=created.record.key_id, now=NOW,
            control_auditor=service.control_auditor,
        )

    # The revocation unwound with its failed audit write: the key is still active.
    assert repo.get_by_id(created.record.key_id).status == "active"


def test_sqlite_rotation_does_not_emit_a_key_revoked_event() -> None:
    # Rotation revokes predecessors internally via repository.revoke_key; those
    # revokes must NOT be double-audited as key_revoked events — one key_rotated
    # event covers the whole rotation.
    from vinctor_service.key_ops import rotate_workspace_key

    service, repo = _key_service_and_repo()
    repo.create_workspace_key(workspace_id="ws_main", now=NOW)
    rotate_workspace_key(
        repo, workspace_id="ws_main", now=NOW,
        control_auditor=service.control_auditor,
    )
    events = _control_events(service)
    assert [e.event_type for e in events] == ["key_rotated"]


def test_key_revoke_rejects_an_auditor_on_a_different_connection() -> None:
    import pytest

    from vinctor_service.key_ops import revoke_local_key

    service, repo = _key_service_and_repo()
    created = repo.create_agent_key(workspace_id="ws_main", agent_id="agent_a", now=NOW)
    other = _sqlite_service()
    with pytest.raises(ValueError, match="SAME connection"):
        revoke_local_key(
            repo, key_id=created.record.key_id, now=NOW,
            control_auditor=other.control_auditor,
        )
    # Fail closed BEFORE any write: the key is untouched.
    assert repo.get_by_id(created.record.key_id).status == "active"


# --- end to end: one chain, ordering, no agent-facing disclosure -----------


def _run_all_control_ops(service, tmp_path) -> None:
    from vinctor_service.key_ops import rotate_workspace_key
    from vinctor_service.keys import SQLiteLocalKeyRepository
    from vinctor_service.policy_files import rollback_policy_version

    repo = service.agent_enforcement_settings_repository
    repo.set_require_boundary(
        workspace_id="ws_main", agent_id="", require_boundary=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_a", require_subject_token=True, now=NOW
    )
    repo.set_require_pop(
        workspace_id="ws_main", agent_id="agent_a", require_pop=True, now=NOW
    )
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main", agent_id="agent_a", scopes=("read:repo/a",), now=NOW
    )
    applied = _apply(service, tmp_path)
    rollback_policy_version(
        service=service, workspace_id="ws_main",
        version=applied.policy_version, applied_by="operator:a", now=NOW,
    )
    rotate_workspace_key(
        SQLiteLocalKeyRepository(service.conn), workspace_id="ws_main", now=NOW,
        control_auditor=service.control_auditor,
    )


def test_sqlite_all_control_ops_share_the_chain_and_order_before_decisions(
    tmp_path,
) -> None:
    from vinctor_service.models import V1EnforceRequest

    service = _sqlite_service()
    _run_all_control_ops(service, tmp_path)

    # A decision event AFTER the rule changes: its chain position proves the
    # rules were changed BEFORE the action — the ordering IS the evidence.
    service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main", agent_id="agent_a", grant_ref="grt_missing",
            action="read", resource="repo/a",
        ),
        now=NOW,
    )

    events = service.audit_writer.list_all()
    control = [e for e in events if e.event_class == "control"]
    decisions = [e for e in events if e.event_class == "decision"]
    assert [e.event_type for e in control] == [
        "enforcement_setting_changed",
        "enforcement_setting_changed",
        "enforcement_setting_changed",
        "scope_bounds_set",
        "policy_applied",
        "policy_rolled_back",
        "key_rotated",
    ]
    assert len(decisions) == 1

    verification = service.audit_writer.verify_chain()
    assert verification.ok is True and verification.count == 8
    # seq order on the ONE chain: every control event precedes the decision.
    seq_by_id = {
        row[1]: row[0]
        for row in service.conn.execute(
            "SELECT seq, event_id FROM audit_events"
        ).fetchall()
    }
    decision_seq = seq_by_id[decisions[0].event_id]
    assert all(seq_by_id[e.event_id] < decision_seq for e in control)


def test_control_ops_do_not_change_the_agent_facing_deny_surface(tmp_path) -> None:
    # ADR 0019 no-disclosure invariant: control events are operator-visible,
    # but an agent's deny response is byte-identical whether or not control
    # operations ever happened — no new reason codes, no new fields.
    from vinctor_service.models import V1EnforceRequest

    request = V1EnforceRequest(
        workspace_id="ws_main", agent_id="agent_a", grant_ref="grt_missing",
        action="read", resource="repo/a",
    )

    pristine = _sqlite_service().enforce(request, now=NOW)

    exercised_service = _sqlite_service()
    _run_all_control_ops(exercised_service, tmp_path)
    exercised = exercised_service.enforce(request, now=NOW)

    assert exercised.status_code == pristine.status_code
    assert exercised.decision == pristine.decision
    assert exercised.error == pristine.error
    assert exercised.reason == pristine.reason


# --- fail-closed wiring guards (Codex review round 1) ----------------------


def test_composite_nesting_is_rejected() -> None:
    import pytest

    auditor, writer = _auditor()
    with pytest.raises(RuntimeError, match="do not nest"), auditor.composite() as pending:
        pending.set(
            event_type="policy_applied", workspace_id="ws_main",
            action="policy_apply", resource="policy/version/1",
            reason="", now=NOW,
        )
        with auditor.composite():
            pass
    assert writer.events == []


def test_composite_requires_an_open_transaction_on_the_bound_connection() -> None:
    # Without the caller's transaction, the suppressed inner mutations would
    # each self-commit while their records are swallowed — committed rule
    # changes with no audit trail. Fail closed at entry.
    import pytest

    service = _sqlite_service()
    with (
        pytest.raises(RuntimeError, match="requires an open transaction"),
        service.control_auditor.composite(),
    ):
        pass


def test_sqlite_repos_reject_an_auditor_on_a_different_connection() -> None:
    import pytest

    from vinctor_service.control_audit import ControlPlaneAuditor
    from vinctor_service.sqlite import (
        SQLiteAgentEnforcementSettingsRepository,
        SQLiteAgentIssuableScopeBoundsRepository,
        SQLiteAuditWriter,
        SQLiteAutoApprovalRuleRepository,
        SQLiteBoundaryRegistry,
    )

    service = _sqlite_service()
    other = _sqlite_service()
    foreign_auditor = ControlPlaneAuditor(SQLiteAuditWriter(other.conn))
    with pytest.raises(ValueError, match="SAME connection"):
        SQLiteAgentEnforcementSettingsRepository(service.conn, foreign_auditor)
    with pytest.raises(ValueError, match="SAME connection"):
        SQLiteAgentIssuableScopeBoundsRepository(service.conn, foreign_auditor)
    with pytest.raises(ValueError, match="SAME connection"):
        SQLiteBoundaryRegistry(service.conn, foreign_auditor)
    with pytest.raises(ValueError, match="SAME connection"):
        SQLiteAutoApprovalRuleRepository(service.conn, foreign_auditor)


def test_sqlite_repos_reject_a_connectionless_auditor() -> None:
    # An in-memory writer cannot commit atomically with the mutation: the
    # setting would land durably while its "audit" lived in process memory.
    import pytest

    from vinctor_service.audit import InMemoryAuditWriter
    from vinctor_service.control_audit import ControlPlaneAuditor
    from vinctor_service.sqlite import SQLiteAgentEnforcementSettingsRepository

    service = _sqlite_service()
    with pytest.raises(ValueError, match="durable"):
        SQLiteAgentEnforcementSettingsRepository(
            service.conn, ControlPlaneAuditor(InMemoryAuditWriter())
        )


def test_rotation_rejects_an_auditor_on_a_different_connection() -> None:
    import pytest

    from vinctor_service.key_ops import rotate_workspace_key

    service, repo = _key_service_and_repo()
    other = _sqlite_service()
    with pytest.raises(ValueError, match="SAME connection"):
        rotate_workspace_key(
            repo, workspace_id="ws_main", now=NOW,
            control_auditor=other.control_auditor,
        )
    # Fail closed BEFORE any write: nothing was minted or revoked.
    assert repo.list_for_workspace("ws_main") == ()


def test_rotation_refuses_a_repository_with_no_verifiable_connection() -> None:
    # An identity check that cannot run is a bypass: a repository proxy that
    # hides its connection is refused rather than trusted.
    import pytest

    from vinctor_service.key_ops import rotate_workspace_key

    service, repo = _key_service_and_repo()

    class _OpaqueRepo:
        def __getattr__(self, name):
            if name == "_conn":  # a proxy hiding the backing connection
                raise AttributeError(name)
            return getattr(repo, name)

    with pytest.raises(ValueError, match="no connection to verify"):
        rotate_workspace_key(
            _OpaqueRepo(), workspace_id="ws_main", now=NOW,
            control_auditor=service.control_auditor,
        )
    assert repo.list_for_workspace("ws_main") == ()
