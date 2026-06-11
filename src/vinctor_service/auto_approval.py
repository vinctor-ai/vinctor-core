from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from vinctor_core.scope import is_valid_grant_scope
from vinctor_service.models import (
    AutoApprovalEvaluationResult,
    AutoApprovalRule,
    GrantRequest,
)
from vinctor_service.repositories import AutoApprovalRuleRepository


def create_auto_approval_rule(
    *,
    rule_repository: AutoApprovalRuleRepository,
    rule: AutoApprovalRule,
) -> AutoApprovalRule:
    _validate_rule(rule)
    rule_repository.add_rule(rule)
    return rule


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
        any(_scope_within_allowed_scope(requested, allowed) for allowed in allowed_scopes)
        for requested in requested_scopes
    )


def _scope_within_allowed_scope(requested_scope: str, allowed_scope: str) -> bool:
    if requested_scope == allowed_scope:
        return True

    requested_action, _, requested_resource = requested_scope.partition(":")
    allowed_action, _, allowed_resource = allowed_scope.partition(":")
    if requested_action != allowed_action or not allowed_resource.endswith("/*"):
        return False

    return requested_resource.startswith(allowed_resource.removesuffix("*"))
