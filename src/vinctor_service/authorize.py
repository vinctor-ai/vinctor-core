from __future__ import annotations

from datetime import datetime

from vinctor_core.models import BoundaryLookup, Grant, PolicyInput, PolicyResult
from vinctor_core.policy import evaluate_policy
from vinctor_service.models import AuthorizationRequest, AuthorizationResponse


def authorize_action(
    request: AuthorizationRequest,
    *,
    grants: tuple[Grant, ...],
    now: datetime,
    boundary_registry: BoundaryLookup | None = None,
) -> AuthorizationResponse:
    policy_result = evaluate_policy(
        PolicyInput(
            workspace_id=request.workspace_id,
            agent_id=request.agent_id,
            grants=grants,
            action=request.action,
            resource=request.resource,
            now=now,
            boundary_id=request.boundary_id,
            boundary_registry=boundary_registry,
        )
    )
    return _response_from_policy_result(request, policy_result)


def _response_from_policy_result(
    request: AuthorizationRequest,
    policy_result: PolicyResult,
) -> AuthorizationResponse:
    return AuthorizationResponse(
        decision=policy_result.decision,
        reason=policy_result.reason,
        workspace_id=policy_result.workspace_id,
        agent_id=policy_result.agent_id,
        action=policy_result.action,
        resource=policy_result.resource,
        scope_attempted=policy_result.scope_attempted,
        scope_matched=policy_result.scope_matched,
        grant_id=policy_result.grant_id,
        grant_ref=policy_result.grant_ref,
        boundary_id=request.boundary_id,
    )
