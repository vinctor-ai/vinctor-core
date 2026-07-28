from __future__ import annotations

from collections.abc import Iterator

from vinctor_core.enforce import evaluate_enforce
from vinctor_core.models import DecisionResult, EnforceInput, Grant, PolicyInput, PolicyResult
from vinctor_core.scope import (
    attempted_scope,
    is_valid_requested_action,
    is_valid_requested_resource,
)


def evaluate_policy(policy_input: PolicyInput) -> PolicyResult:
    scope_attempted = attempted_scope(policy_input.action, policy_input.resource)

    if not is_valid_requested_action(policy_input.action):
        return _deny(policy_input, "invalid_action", scope_attempted)
    if not is_valid_requested_resource(policy_input.resource):
        return _deny(policy_input, "invalid_resource", scope_attempted)

    for grant in _candidate_grants(policy_input):
        result = evaluate_enforce(
            EnforceInput(
                grant=grant,
                action=policy_input.action,
                resource=policy_input.resource,
                now=policy_input.now,
                boundary_id=policy_input.boundary_id,
                boundary_registry=policy_input.boundary_registry,
            )
        )
        if result.decision == "permit":
            return _from_enforce_result(policy_input, result)
        if result.reason.startswith("boundary_"):
            return _from_enforce_result(policy_input, result)
        if result.reason in {
            "invalid_action",
            "invalid_resource",
            "invalid_grant_scope",
        }:
            return _from_enforce_result(policy_input, result)

    return _deny(policy_input, "no_applicable_grant", scope_attempted)


def _candidate_grants(policy_input: PolicyInput) -> Iterator[Grant]:
    return (
        grant
        for grant in policy_input.grants
        if grant.workspace_id == policy_input.workspace_id
        and grant.agent_id == policy_input.agent_id
    )


def _from_enforce_result(
    policy_input: PolicyInput,
    result: DecisionResult,
) -> PolicyResult:
    return PolicyResult(
        decision=result.decision,
        reason=result.reason,
        workspace_id=policy_input.workspace_id,
        agent_id=policy_input.agent_id,
        action=policy_input.action,
        resource=policy_input.resource,
        scope_attempted=result.scope_attempted,
        scope_matched=result.scope_matched,
        grant_id=result.grant_id,
        grant_ref=result.grant_ref,
        enforce_result=result,
    )


def _deny(
    policy_input: PolicyInput,
    reason: str,
    scope_attempted: str,
) -> PolicyResult:
    return PolicyResult(
        decision="deny",
        reason=reason,
        workspace_id=policy_input.workspace_id,
        agent_id=policy_input.agent_id,
        action=policy_input.action,
        resource=policy_input.resource,
        scope_attempted=scope_attempted,
        scope_matched=None,
    )
