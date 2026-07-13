from __future__ import annotations

from vinctor_core.models import Boundary, DecisionResult, EnforceInput
from vinctor_core.scope import (
    attempted_scope,
    is_valid_grant_scope,
    is_valid_requested_action,
    is_valid_requested_resource,
    match_scope,
)


def evaluate_enforce(enforce_input: EnforceInput) -> DecisionResult:
    grant = enforce_input.grant
    scope_attempted = attempted_scope(enforce_input.action, enforce_input.resource)

    boundary_result = _resolve_boundary(enforce_input)
    if isinstance(boundary_result, DecisionResult):
        return boundary_result
    boundary = boundary_result

    if not is_valid_requested_action(enforce_input.action):
        return _deny(enforce_input, "invalid_action", scope_attempted, boundary=boundary)
    if not is_valid_requested_resource(enforce_input.resource):
        return _deny(enforce_input, "invalid_resource", scope_attempted, boundary=boundary)

    if grant.status == "revoked":
        return _deny(enforce_input, "grant_revoked", scope_attempted, boundary=boundary)
    if grant.status == "expired":
        return _deny(enforce_input, "grant_expired", scope_attempted, boundary=boundary)
    if grant.status != "active":
        return _deny(enforce_input, "grant_not_active", scope_attempted, boundary=boundary)
    if grant.expires_at is not None and grant.expires_at <= enforce_input.now:
        return _deny(enforce_input, "grant_expired", scope_attempted, boundary=boundary)
    if any(not is_valid_grant_scope(scope) for scope in grant.scopes):
        return _deny(enforce_input, "invalid_grant_scope", scope_attempted, boundary=boundary)

    matched = match_scope(grant.scopes, enforce_input.action, enforce_input.resource)
    if matched is None:
        return _deny(enforce_input, "action_denied", scope_attempted, boundary=boundary)

    return DecisionResult(
        decision="permit",
        reason="permitted",
        grant_id=grant.grant_id,
        grant_ref=grant.grant_ref,
        workspace_id=grant.workspace_id,
        agent_id=grant.agent_id,
        action=enforce_input.action,
        resource=enforce_input.resource,
        scope_attempted=scope_attempted,
        scope_matched=matched,
        boundary=boundary,
        attempted_boundary_id=enforce_input.boundary_id,
    )


def _resolve_boundary(enforce_input: EnforceInput) -> Boundary | DecisionResult | None:
    boundary_id = enforce_input.boundary_id
    if boundary_id is None:
        if enforce_input.require_boundary:
            return _deny(
                enforce_input,
                "boundary_required",
                attempted_scope(enforce_input.action, enforce_input.resource),
            )
        return None

    registry = enforce_input.boundary_registry
    boundary = registry.get(boundary_id) if registry is not None else None
    scope_attempted = attempted_scope(enforce_input.action, enforce_input.resource)
    if boundary is None:
        return _deny(
            enforce_input,
            "boundary_not_found",
            scope_attempted,
            attempted_boundary_id=boundary_id,
        )
    if boundary.workspace_id != enforce_input.grant.workspace_id:
        return _deny(
            enforce_input,
            "boundary_wrong_workspace",
            scope_attempted,
            attempted_boundary_id=boundary_id,
        )
    if boundary.status != "active":
        return _deny(
            enforce_input,
            "boundary_inactive",
            scope_attempted,
            boundary=boundary,
            attempted_boundary_id=boundary_id,
        )
    return boundary


def _deny(
    enforce_input: EnforceInput,
    reason: str,
    scope_attempted: str,
    *,
    boundary: Boundary | None = None,
    attempted_boundary_id: str | None = None,
) -> DecisionResult:
    grant = enforce_input.grant
    return DecisionResult(
        decision="deny",
        reason=reason,
        grant_id=grant.grant_id,
        grant_ref=grant.grant_ref,
        workspace_id=grant.workspace_id,
        agent_id=grant.agent_id,
        action=enforce_input.action,
        resource=enforce_input.resource,
        scope_attempted=scope_attempted,
        scope_matched=None,
        boundary=boundary,
        attempted_boundary_id=attempted_boundary_id or enforce_input.boundary_id,
    )
