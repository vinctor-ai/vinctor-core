from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import token_urlsafe

from vinctor_core.models import AuditEvent, DecisionResult


@dataclass(frozen=True)
class AuditEventInput:
    decision: DecisionResult
    event_id: str | None = None
    created_at: datetime | None = None
    enforcing_principal: str | None = None


def build_audit_event(audit_input: AuditEventInput) -> AuditEvent:
    decision = audit_input.decision
    boundary = decision.boundary
    boundary_id = boundary.boundary_id if boundary else decision.attempted_boundary_id

    return AuditEvent(
        event_id=audit_input.event_id or _new_event_id(),
        event_type="action_permitted" if decision.decision == "permit" else "action_denied",
        decision=decision.decision,
        reason=decision.reason,
        workspace_id=decision.workspace_id,
        agent_id=decision.agent_id,
        grant_id=decision.grant_id,
        grant_ref=decision.grant_ref,
        action=decision.action,
        resource=decision.resource,
        scope_attempted=decision.scope_attempted,
        scope_matched=decision.scope_matched,
        boundary_id=boundary_id,
        runtime=boundary.runtime if boundary else None,
        boundary_type=boundary.boundary_type if boundary else None,
        created_at=audit_input.created_at or datetime.now(UTC),
        enforcing_principal=audit_input.enforcing_principal,
    )


def build_rejection_audit_event(
    *,
    reason: str,
    workspace_id: str,
    agent_id: str,
    created_at: datetime,
    event_type: str = "access_rejected",
    action: str = "",
    resource: str = "",
    scope_attempted: str | None = None,
    boundary_id: str | None = None,
    enforcing_principal: str | None = None,
    event_id: str | None = None,
) -> AuditEvent:
    """Build an audit event for a request rejected BEFORE grant-scope evaluation.

    Per ADR 0008, security-relevant pre-grant rejections (e.g. an agent naming a
    grant that is not its own, or an operator over-issuing beyond an agent's
    bounds) are recorded for the operator, while the caller-facing response stays
    generic and leak-free. The event records the attributable principal and a
    coarse ``reason`` code, and deliberately discloses no grant identifiers:
    ``grant_id``/``grant_ref`` are empty so the offending grant is never revealed
    in the trail. ``scope_attempted`` defaults to ``action:resource`` (the enforce
    case) but can be set explicitly (e.g. the requested scopes of an issuance).
    """
    return AuditEvent(
        event_id=event_id or _new_event_id(),
        event_type=event_type,
        decision="deny",
        reason=reason,
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_id="",
        grant_ref="",
        action=action,
        resource=resource,
        scope_attempted=scope_attempted if scope_attempted is not None else f"{action}:{resource}",
        scope_matched=None,
        boundary_id=boundary_id,
        runtime=None,
        boundary_type=None,
        created_at=created_at,
        enforcing_principal=enforcing_principal,
    )


def _new_event_id() -> str:
    return f"evt_{token_urlsafe(12)}"
