from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from vinctor_core.audit import (
    REASON_AGENT_GRANT_MISMATCH,
    AuditEventInput,
    build_audit_event,
    build_rejection_audit_event,
)
from vinctor_core.enforce import evaluate_enforce
from vinctor_core.models import AuditEvent, BoundaryLookup, EnforceInput
from vinctor_core.scope import is_valid_requested_action, is_valid_requested_resource
from vinctor_service.audit import AuditWriter
from vinctor_service.models import V1SimulateRequest, V1SimulateResponse
from vinctor_service.repositories import (
    AgentEnforcementSettingsRepository,
    GrantRepository,
)

_GRANT_FORBIDDEN_MESSAGE = "grant is not accessible for this request"


def simulate_v1_contract(
    request: V1SimulateRequest,
    *,
    grant_repository: GrantRepository,
    now: datetime,
    audit_writer: AuditWriter,
    boundary_registry: BoundaryLookup | None = None,
    agent_enforcement_settings_repository: AgentEnforcementSettingsRepository | None = None,
) -> V1SimulateResponse:
    """Calculate and audit an enforce result without turning it into a gate."""
    try:
        grant = grant_repository.get_by_ref(request.grant_ref)
    except Exception:
        return _error(503, "service_unavailable", "grant lookup failed; no simulation was recorded")

    if grant is None or (
        grant.workspace_id != request.workspace_id or grant.agent_id != request.agent_id
    ):
        event = build_rejection_audit_event(
            reason_code=REASON_AGENT_GRANT_MISMATCH,
            workspace_id=request.workspace_id,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            created_at=now,
            boundary_id=request.boundary_id,
            event_type="action_would_deny",
        )
        if not _write(audit_writer, event):
            return _error(
                503,
                "service_unavailable",
                "audit write failed; no simulation was recorded",
            )
        return V1SimulateResponse(
            status_code=200,
            would_decision="deny",
            error="forbidden",
            reason=_GRANT_FORBIDDEN_MESSAGE,
            audit_event_id=event.event_id,
        )

    if not is_valid_requested_action(request.action):
        return _error(400, "scope_invalid", f"action '{request.action}' is not valid")
    if not is_valid_requested_resource(request.resource):
        return _error(400, "scope_invalid", f"resource '{request.resource}' is not valid")

    require_boundary = (
        agent_enforcement_settings_repository.is_boundary_required(
            workspace_id=request.workspace_id,
            agent_id=request.agent_id,
        )
        if agent_enforcement_settings_repository is not None
        else False
    )
    decision = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action=request.action,
            resource=request.resource,
            now=now,
            boundary_id=request.boundary_id,
            boundary_registry=boundary_registry,
            require_boundary=require_boundary,
        )
    )
    event = replace(
        build_audit_event(AuditEventInput(decision=decision, created_at=now)),
        event_type=(
            "action_would_permit" if decision.decision == "permit" else "action_would_deny"
        ),
    )
    if not _write(audit_writer, event):
        return _error(
            503,
            "service_unavailable",
            "audit write failed; no simulation was recorded",
        )

    # No-disclosure: like enforce, the agent-facing simulate response carries
    # only the would-decision, coarse reason codes, and the audit_event_id; the
    # grant/scope detail stays in the operator-only audit event written above.
    return V1SimulateResponse(
        status_code=200,
        would_decision=decision.decision,
        error=None if decision.decision == "permit" else decision.reason,
        reason=None if decision.decision == "permit" else decision.reason,
        audit_event_id=event.event_id,
    )


def _write(audit_writer: AuditWriter, event: AuditEvent) -> bool:
    try:
        audit_writer.write(event)
    except Exception:
        return False
    return True


def _error(status_code: int, error: str, reason: str) -> V1SimulateResponse:
    return V1SimulateResponse(status_code=status_code, error=error, reason=reason)
