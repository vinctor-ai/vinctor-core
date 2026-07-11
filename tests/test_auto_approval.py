from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_service import (
    AutoApprovalRule,
    GrantRequestCreateRequest,
    SQLiteV1Service,
    V1EnforceRequest,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    return sqlite3.connect(tmp_path / "vinctor.sqlite")


def rule(
    *,
    rule_id: str = "apr_ci",
    allowed_scopes: tuple[str, ...] = ("execute:ci/*",),
    max_ttl_seconds: int = 3600,
    target_agent_id: str = "agent_runner",
    status: str = "active",
) -> AutoApprovalRule:
    return AutoApprovalRule(
        rule_id=rule_id,
        workspace_id="ws_main",
        name="CI auto approval",
        target_agent_id=target_agent_id,
        allowed_scopes=allowed_scopes,
        max_ttl_seconds=max_ttl_seconds,
        status=status,
        created_by="workspace:ws_main",
        created_at=NOW,
    )


def request(
    *,
    scopes: tuple[str, ...] = ("execute:ci/test",),
    ttl_seconds: int = 1800,
):
    return GrantRequestCreateRequest(
        workspace_id="ws_main",
        requester_agent_id="agent_runner",
        requested_scopes=scopes,
        requested_ttl_seconds=ttl_seconds,
        reason="run CI validation",
        request_id="grq_ci",
    )


def pending_request(service: SQLiteV1Service, *, request_body=None):
    created = service.create_grant_request(request_body or request(), now=NOW)
    assert created.request is not None
    return created.request


def test_auto_approval_rule_can_be_created_listed_and_disabled(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    created = service.create_auto_approval_rule(rule())

    assert service.list_auto_approval_rules(workspace_id="ws_main") == (created,)

    disabled = service.disable_auto_approval_rule(
        rule_id="apr_ci",
        workspace_id="ws_main",
        disabled_by="workspace:ws_main",
        now=NOW,
    )

    assert disabled is not None
    assert disabled.status == "disabled"
    assert disabled.updated_by == "workspace:ws_main"
    conn.close()


def test_auto_approval_dry_run_matches_scope_and_ttl(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_auto_approval_rule(rule())
    grant_request = pending_request(service)

    result = service.evaluate_auto_approval(request=grant_request)

    assert result.decision == "would_approve"
    assert result.reason == "auto_approval_match"
    assert result.rule is not None
    assert result.rule.rule_id == "apr_ci"
    assert service.lookup_grant_request(
        request_id="grq_ci",
        workspace_id="ws_main",
    ).status == "pending"
    assert service.lookup_grant(grant_ref="grt_missing", workspace_id="ws_main") is None
    assert [event.event_type for event in service.audit_events] == ["grant_requested"]
    conn.close()


def test_auto_approval_dry_run_rejects_scope_outside_rule(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_auto_approval_rule(rule(allowed_scopes=("execute:ci/test",)))
    grant_request = pending_request(
        service,
        request_body=request(scopes=("execute:deploy/production",)),
    )

    result = service.evaluate_auto_approval(request=grant_request)

    assert result.decision == "would_not_approve"
    assert result.reason == "scope_outside_rule"
    assert result.rule is None
    conn.close()


def test_auto_approval_dry_run_rejects_ttl_above_rule(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_auto_approval_rule(rule(max_ttl_seconds=900))
    grant_request = pending_request(service, request_body=request(ttl_seconds=1800))

    result = service.evaluate_auto_approval(request=grant_request)

    assert result.decision == "would_not_approve"
    assert result.reason == "ttl_exceeds_rule"
    conn.close()


def test_auto_approval_dry_run_uses_later_matching_rule(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_auto_approval_rule(rule(rule_id="apr_short", max_ttl_seconds=900))
    service.create_auto_approval_rule(rule(rule_id="apr_long", max_ttl_seconds=3600))
    grant_request = pending_request(service, request_body=request(ttl_seconds=1800))

    result = service.evaluate_auto_approval(request=grant_request)

    assert result.decision == "would_approve"
    assert result.rule is not None
    assert result.rule.rule_id == "apr_long"
    conn.close()


def test_auto_approval_dry_run_ignores_disabled_rules(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_auto_approval_rule(rule(status="disabled"))
    grant_request = pending_request(service)

    result = service.evaluate_auto_approval(request=grant_request)

    assert result.decision == "would_not_approve"
    assert result.reason == "no_matching_rule"
    conn.close()


def test_auto_approval_dry_run_rejects_decided_requests(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.create_auto_approval_rule(rule())
    grant_request = pending_request(service)
    rejected = service.reject_grant_request(
        request_id=grant_request.request_id,
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        decision_reason="manual reject",
        now=NOW,
    )
    assert rejected.request is not None

    result = service.evaluate_auto_approval(request=rejected.request)

    assert result.decision == "would_not_approve"
    assert result.reason == "grant_request_not_pending"
    conn.close()


def test_auto_approval_service_path_approves_and_issues_grant(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_auto_approval_rule(rule())
    pending_request(service)

    approved = service.auto_approve_grant_request(
        request_id="grq_ci",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        now=NOW + timedelta(seconds=1),
    )

    assert approved.status == "approved"
    assert approved.reason == "grant_request_auto_approved"
    assert approved.auto_approval_rule_id == "apr_ci"
    assert approved.request is not None
    assert approved.request.status == "approved"
    assert approved.request.decided_by == "workspace:ws_main"
    assert approved.request.decision_reason == "auto_approval_rule:apr_ci"
    assert approved.grant is not None
    assert approved.request.issued_grant_ref == approved.grant.grant_ref

    enforced = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_main",
            agent_id="agent_runner",
            grant_ref=approved.grant.grant_ref,
            action="execute",
            resource="ci/test",
        ),
        now=NOW + timedelta(seconds=2),
    )

    assert enforced.status_code == 200
    assert enforced.decision == "permit"
    assert [event.event_type for event in service.audit_events] == [
        "grant_requested",
        "grant_issued",
        "grant_request_auto_approved",
        "action_permitted",
    ]
    conn.close()


def test_auto_approval_service_path_leaves_non_matching_request_pending(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:deploy/production",),
        now=NOW,
    )
    service.create_auto_approval_rule(rule(allowed_scopes=("execute:ci/test",)))
    pending_request(
        service,
        request_body=request(scopes=("execute:deploy/production",)),
    )

    result = service.auto_approve_grant_request(
        request_id="grq_ci",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        now=NOW + timedelta(seconds=1),
    )

    assert result.status == "failed"
    assert result.reason == "scope_outside_rule"
    assert result.request is not None
    assert result.request.status == "pending"
    assert result.grant is None
    assert service.list_grant_requests(workspace_id="ws_main") == (result.request,)
    assert [event.event_type for event in service.audit_events] == ["grant_requested"]
    conn.close()


def test_auto_approval_service_path_ignores_disabled_rule(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_auto_approval_rule(rule(status="disabled"))
    pending_request(service)

    result = service.auto_approve_grant_request(
        request_id="grq_ci",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        now=NOW + timedelta(seconds=1),
    )

    assert result.status == "failed"
    assert result.reason == "no_matching_rule"
    assert result.request is not None
    assert result.request.status == "pending"
    assert result.grant is None
    assert [event.event_type for event in service.audit_events] == ["grant_requested"]
    conn.close()


def test_auto_approval_service_path_rejects_rule_ttl_excess(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_auto_approval_rule(rule(max_ttl_seconds=900))
    pending_request(service, request_body=request(ttl_seconds=1800))

    result = service.auto_approve_grant_request(
        request_id="grq_ci",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        now=NOW + timedelta(seconds=1),
    )

    assert result.status == "failed"
    assert result.reason == "ttl_exceeds_rule"
    assert result.request is not None
    assert result.request.status == "pending"
    assert result.grant is None
    assert [event.event_type for event in service.audit_events] == ["grant_requested"]
    conn.close()


def test_auto_approval_service_path_still_requires_agent_issuable_bounds(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.create_auto_approval_rule(rule(allowed_scopes=("execute:deploy/*",)))
    pending_request(
        service,
        request_body=request(scopes=("execute:deploy/production",)),
    )

    result = service.auto_approve_grant_request(
        request_id="grq_ci",
        workspace_id="ws_main",
        decided_by="workspace:ws_main",
        now=NOW + timedelta(seconds=1),
    )

    assert result.status == "failed"
    assert result.reason == "scope_outside_issuable_bounds"
    assert result.request is not None
    assert result.request.status == "pending"
    assert result.grant is None
    assert service.lookup_grant_request(
        request_id="grq_ci",
        workspace_id="ws_main",
    ).status == "pending"
    # ADR 0008: the auto-approval's out-of-bounds issuance attempt is recorded.
    assert [event.event_type for event in service.audit_events] == [
        "grant_requested",
        "grant_issue_rejected",
    ]
    conn.close()
