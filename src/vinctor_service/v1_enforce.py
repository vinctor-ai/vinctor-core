from __future__ import annotations

from datetime import datetime

from vinctor_core.audit import AuditEventInput, build_audit_event
from vinctor_core.enforce import evaluate_enforce
from vinctor_core.models import (
    AuditEvent,
    BoundaryLookup,
    DecisionResult,
    EnforceInput,
    Grant,
)
from vinctor_core.scope import is_valid_requested_action, is_valid_requested_resource
from vinctor_service.audit import AuditWriter
from vinctor_service.models import (
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
    V1EnforceResponse,
)
from vinctor_service.repositories import GrantRepository


def enforce_v1_contract(
    request: V1EnforceRequest,
    *,
    grant_repository: GrantRepository,
    now: datetime,
    audit_writer: AuditWriter,
    boundary_registry: BoundaryLookup | None = None,
) -> V1EnforceResponse:
    try:
        grant = grant_repository.get_by_ref(request.grant_ref)
    except Exception:
        return _pre_audit_error(
            503,
            "service_unavailable",
            "grant lookup failed; no decision was recorded",
        )

    if grant is None:
        return _pre_audit_error(
            404,
            "grant_not_found",
            f"grant_ref {request.grant_ref} does not exist",
        )

    if grant.workspace_id != request.workspace_id or grant.agent_id != request.agent_id:
        return _pre_audit_error(
            403,
            "forbidden",
            f"grant_ref {request.grant_ref} does not belong to the requesting agent",
        )

    return _evaluate_and_record(
        grant=grant,
        action=request.action,
        resource=request.resource,
        boundary_id=request.boundary_id,
        now=now,
        audit_writer=audit_writer,
        boundary_registry=boundary_registry,
    )


def delegated_enforce_v1_contract(
    request: V1DelegatedEnforceRequest,
    *,
    grant_repository: GrantRepository,
    now: datetime,
    audit_writer: AuditWriter,
    boundary_registry: BoundaryLookup | None = None,
    pep_workspace_id: str | None = None,
) -> V1EnforceResponse:
    """Resolve an on-behalf-of enforce request from a PEP (see ADR 0007).

    The PEP authenticates with its own key; the asserted subject workspace must
    equal the PEP's own workspace, and the grant must belong to the asserted
    subject. This preserves tenant isolation: a PEP can never authorize a
    subject or grant in another workspace. The enforcing PEP principal is
    recorded separately from the subject ``agent_id`` in the audit trail.
    """
    pep_workspace = pep_workspace_id or request.pep_workspace_id or request.workspace_id

    try:
        grant = grant_repository.get_by_ref(request.grant_ref)
    except Exception:
        return _pre_audit_error(
            503,
            "service_unavailable",
            "grant lookup failed; no decision was recorded",
        )

    if grant is None:
        return _pre_audit_error(
            404,
            "grant_not_found",
            f"grant_ref {request.grant_ref} does not exist",
        )

    # Tenant isolation: the asserted subject workspace is forced to the PEP's
    # own workspace, and the grant must belong to the asserted subject.
    if (
        request.workspace_id != pep_workspace
        or grant.workspace_id != request.workspace_id
        or grant.agent_id != request.agent_id
    ):
        return _pre_audit_error(
            403,
            "forbidden",
            f"grant_ref {request.grant_ref} does not belong to the asserted subject",
        )

    return _evaluate_and_record(
        grant=grant,
        action=request.action,
        resource=request.resource,
        boundary_id=request.boundary_id,
        now=now,
        audit_writer=audit_writer,
        boundary_registry=boundary_registry,
        enforcing_principal=request.pep_id,
    )


def _evaluate_and_record(
    *,
    grant: Grant,
    action: str,
    resource: str,
    boundary_id: str | None,
    now: datetime,
    audit_writer: AuditWriter,
    boundary_registry: BoundaryLookup | None,
    enforcing_principal: str | None = None,
) -> V1EnforceResponse:
    if not is_valid_requested_action(action):
        return _pre_audit_error(
            400,
            "scope_invalid",
            _invalid_action_reason(action),
        )

    if not is_valid_requested_resource(resource):
        return _pre_audit_error(
            400,
            "scope_invalid",
            f"resource '{resource}' is not a valid v1 resource path",
        )

    decision = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action=action,
            resource=resource,
            now=now,
            boundary_id=boundary_id,
            boundary_registry=boundary_registry,
        )
    )
    audit_event = build_audit_event(
        AuditEventInput(
            decision=decision,
            created_at=now,
            enforcing_principal=enforcing_principal,
        )
    )

    try:
        audit_writer.write(audit_event)
    except Exception:
        return _pre_audit_error(
            503,
            "service_unavailable",
            "audit write failed; no decision was recorded",
        )

    return _response_from_decision(decision, audit_event)


def _response_from_decision(
    decision: DecisionResult,
    audit_event: AuditEvent,
) -> V1EnforceResponse:
    if decision.decision == "permit":
        return V1EnforceResponse(
            status_code=200,
            decision="permit",
            grant_id=decision.grant_id,
            agent_id=decision.agent_id,
            scope_matched=decision.scope_matched,
            audit_event_id=audit_event.event_id,
        )

    return V1EnforceResponse(
        status_code=403,
        decision="deny",
        error=decision.reason,
        reason=_deny_reason(decision),
        grant_id=decision.grant_id,
        agent_id=decision.agent_id,
        audit_event_id=audit_event.event_id,
    )


def _pre_audit_error(status_code: int, error: str, reason: str) -> V1EnforceResponse:
    return V1EnforceResponse(status_code=status_code, error=error, reason=reason)


def _invalid_action_reason(action: str) -> str:
    if action == "push":
        return (
            "action 'push' is not a recognized v1 action verb; "
            "use 'write' for git push operations"
        )
    return f"action '{action}' is not a recognized v1 action verb"


def _deny_reason(decision: DecisionResult) -> str:
    if decision.reason == "action_denied":
        return f"scope {decision.scope_attempted} is not covered by grant {decision.grant_id}"
    if decision.reason == "grant_revoked":
        return f"grant {decision.grant_id} is revoked"
    if decision.reason == "grant_expired":
        return f"grant {decision.grant_id} is expired"
    if decision.reason == "grant_not_active":
        return f"grant {decision.grant_id} is not active"
    if decision.reason.startswith("boundary_"):
        boundary_id = decision.attempted_boundary_id or "unknown"
        return f"boundary {boundary_id} could not be used for this enforce request"
    return decision.reason
