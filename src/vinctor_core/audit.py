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
    )


def _new_event_id() -> str:
    return f"evt_{token_urlsafe(12)}"
