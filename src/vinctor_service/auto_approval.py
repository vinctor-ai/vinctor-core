from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime

from vinctor_core.audit import (
    EVENT_AUTO_APPROVAL_RULE_DISABLED,
    EVENT_AUTO_APPROVAL_RULE_UPDATED,
)
from vinctor_core.scope import is_valid_grant_scope, scope_subsumes
from vinctor_service.audit import AuditWriter
from vinctor_service.grant_requests import approve_grant_request, lookup_grant_request
from vinctor_service.grants import AgentIssuableScopeBoundsRepository
from vinctor_service.models import (
    AutoApprovalEvaluationResult,
    AutoApprovalRule,
    GrantRequest,
    GrantRequestDecisionResult,
)
from vinctor_service.repositories import (
    AutoApprovalRuleRepository,
    GrantLifecycleRepository,
    GrantRequestRepository,
)


@dataclass(frozen=True)
class RuleUpdateControlEvent:
    """Fields for the control event a direct auto-approval-rule update emits.

    A direct update can widen an active rule's scopes, change its target agent
    or TTL, or re-enable it — every one of these must be audited, not just a
    disable (PKA-56 B1). The before/after states pick the event: an active rule
    going disabled keeps the dedicated ``auto_approval_rule_disabled`` event,
    while everything else emits ``auto_approval_rule_updated``. Reasons name
    changed fields without copying scope or target values into the event.
    """

    event_type: str
    action: str
    reason: str
    scope_attempted: str


_AUDITED_RULE_FIELDS = (
    "name",
    "target_agent_id",
    "allowed_scopes",
    "max_ttl_seconds",
    "status",
)


def _changed_rule_fields(
    prior: AutoApprovalRule, rule: AutoApprovalRule
) -> list[str]:
    return [
        field
        for field in _AUDITED_RULE_FIELDS
        if getattr(prior, field) != getattr(rule, field)
    ]


def auto_approval_update_control_event(
    prior: AutoApprovalRule, rule: AutoApprovalRule
) -> RuleUpdateControlEvent:
    changed = _changed_rule_fields(prior, rule)
    if prior.status == "active" and rule.status == "disabled":
        other = [field for field in changed if field != "status"]
        reason = "status=disabled"
        if other:
            reason += f" changed={','.join(other)}"
        return RuleUpdateControlEvent(
            event_type=EVENT_AUTO_APPROVAL_RULE_DISABLED,
            action="disable_auto_approval_rule",
            reason=reason,
            scope_attempted="",
        )
    return RuleUpdateControlEvent(
        event_type=EVENT_AUTO_APPROVAL_RULE_UPDATED,
        action="update_auto_approval_rule",
        reason=f"status={rule.status} changed={','.join(changed) if changed else 'none'}",
        scope_attempted="",
    )


def create_auto_approval_rule(
    *,
    rule_repository: AutoApprovalRuleRepository,
    rule: AutoApprovalRule,
) -> AutoApprovalRule:
    _validate_rule(rule)
    rule_repository.add_rule(rule)
    return rule


def upsert_auto_approval_rule(
    *,
    rule_repository: AutoApprovalRuleRepository,
    rule: AutoApprovalRule,
) -> str:
    _validate_rule(rule)
    existing = rule_repository.get_rule(rule.rule_id)
    if existing is None:
        rule_repository.add_rule(rule)
        return "created"
    if existing.workspace_id != rule.workspace_id:
        raise ValueError("auto-approval rule_id belongs to another workspace")
    rule_repository.update_rule(rule)
    return "updated"


def disable_auto_approval_rule(
    *,
    rule_repository: AutoApprovalRuleRepository,
    rule_id: str,
    workspace_id: str,
    disabled_by: str,
    now: datetime,
) -> AutoApprovalRule | None:
    rule = rule_repository.get_rule(rule_id)
    if rule is None or rule.workspace_id != workspace_id:
        return None
    disabled = replace(
        rule,
        status="disabled",
        updated_by=disabled_by,
        updated_at=now,
    )
    rule_repository.update_rule(disabled)
    return disabled


def list_auto_approval_rules(
    *,
    rule_repository: AutoApprovalRuleRepository,
    workspace_id: str,
) -> tuple[AutoApprovalRule, ...]:
    return rule_repository.list_rules_for_workspace(workspace_id)


def evaluate_auto_approval(
    *,
    request: GrantRequest,
    rule_repository: AutoApprovalRuleRepository,
) -> AutoApprovalEvaluationResult:
    if request.status != "pending":
        return AutoApprovalEvaluationResult(
            decision="would_not_approve",
            reason="grant_request_not_pending",
            request=request,
        )

    saw_scope_candidate = False
    saw_ttl_candidate = False
    for rule in rule_repository.list_rules_for_workspace(request.workspace_id):
        if rule.status != "active" or rule.target_agent_id != request.target_agent_id:
            continue
        if not _scopes_within_rule(request.requested_scopes, rule.allowed_scopes):
            saw_scope_candidate = True
            continue
        if request.requested_ttl_seconds > rule.max_ttl_seconds:
            saw_ttl_candidate = True
            continue
        return AutoApprovalEvaluationResult(
            decision="would_approve",
            reason="auto_approval_match",
            request=request,
            rule=rule,
        )

    if saw_ttl_candidate:
        return AutoApprovalEvaluationResult(
            decision="would_not_approve",
            reason="ttl_exceeds_rule",
            request=request,
        )

    return AutoApprovalEvaluationResult(
        decision="would_not_approve",
        reason="scope_outside_rule" if saw_scope_candidate else "no_matching_rule",
        request=request,
    )


def auto_approve_grant_request(
    *,
    request_id: str,
    workspace_id: str,
    decided_by: str,
    request_repository: GrantRequestRepository,
    rule_repository: AutoApprovalRuleRepository,
    grant_repository: GrantLifecycleRepository,
    scope_bounds_repository: AgentIssuableScopeBoundsRepository,
    audit_writer: AuditWriter,
    now: datetime,
) -> GrantRequestDecisionResult:
    request = lookup_grant_request(
        request_id=request_id,
        workspace_id=workspace_id,
        request_repository=request_repository,
    )
    if request is None:
        return GrantRequestDecisionResult(status="failed", reason="grant_request_not_found")

    evaluation = evaluate_auto_approval(
        request=request,
        rule_repository=rule_repository,
    )
    if evaluation.decision != "would_approve" or evaluation.rule is None:
        return GrantRequestDecisionResult(
            status="failed",
            reason=evaluation.reason,
            request=evaluation.request,
        )

    approved = approve_grant_request(
        request_id=request.request_id,
        workspace_id=request.workspace_id,
        decided_by=decided_by,
        decision_reason=f"auto_approval_rule:{evaluation.rule.rule_id}",
        request_repository=request_repository,
        grant_repository=grant_repository,
        scope_bounds_repository=scope_bounds_repository,
        audit_writer=audit_writer,
        now=now,
        audit_event_type="grant_request_auto_approved",
        audit_reason="grant_request_auto_approved",
        audit_action="auto_approve_grant_request",
    )
    return GrantRequestDecisionResult(
        status=approved.status,
        reason=approved.reason,
        request=approved.request or request,
        grant=approved.grant,
        audit_event_id=approved.audit_event_id,
        auto_approval_rule_id=evaluation.rule.rule_id if approved.status == "approved" else None,
    )


def _validate_rule(rule: AutoApprovalRule) -> None:
    if rule.workspace_id == "":
        raise ValueError("workspace_id must be non-empty")
    if rule.rule_id == "":
        raise ValueError("rule_id must be non-empty")
    if rule.name == "":
        raise ValueError("name must be non-empty")
    if rule.target_agent_id == "":
        raise ValueError("target_agent_id must be non-empty")
    if rule.max_ttl_seconds <= 0:
        raise ValueError("max_ttl_seconds must be positive")
    if rule.status not in {"active", "disabled"}:
        raise ValueError(f"invalid rule status: {rule.status}")
    if not rule.allowed_scopes:
        raise ValueError("at least one allowed scope is required")
    invalid_scopes = [
        scope for scope in rule.allowed_scopes if not is_valid_grant_scope(scope)
    ]
    if invalid_scopes:
        raise ValueError(f"invalid allowed scope: {invalid_scopes[0]}")
    if rule.created_by == "":
        raise ValueError("created_by must be non-empty")


def _scopes_within_rule(
    requested_scopes: tuple[str, ...],
    allowed_scopes: tuple[str, ...],
) -> bool:
    return all(
        any(scope_subsumes(allowed, requested) for allowed in allowed_scopes)
        for requested in requested_scopes
    )
