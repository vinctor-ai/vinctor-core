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
    identity_proven: bool = False
    token_id: str | None = None


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
        identity_proven=audit_input.identity_proven,
        token_id=audit_input.token_id,
    )


# Operator-only audit for security-relevant pre-grant-evaluation rejections
# (ADR 0008). These never alter the caller-facing response.
EVENT_ACCESS_REJECTED = "access_rejected"
EVENT_AUTH_FAILED = "auth_failed"
EVENT_GRANT_ISSUE_REJECTED = "grant_issue_rejected"
EVENT_SUBJECT_TOKEN_MINTED = "subject_token_minted"

# Coarse `reason_code` enum for rejection events. Intentionally low-cardinality
# so the audit trail carries the security signal without leaking specifics.
REASON_AGENT_GRANT_MISMATCH = "agent_grant_mismatch"
REASON_AUTH_FAILED = "auth_failed"
REASON_SCOPE_OUTSIDE_ISSUABLE_BOUNDS = "scope_outside_issuable_bounds"
REASON_ISSUABLE_BOUNDS_NOT_FOUND = "issuable_bounds_not_found"
REASON_TTL_EXCEEDS_ISSUABLE_MAX = "ttl_exceeds_issuable_max"
REASON_SUBJECT_TOKEN_INVALID = "subject_token_invalid"
REASON_SUBJECT_TOKEN_REQUIRED = "subject_token_required"


def build_rejection_audit_event(
    *,
    reason_code: str,
    workspace_id: str,
    agent_id: str,
    created_at: datetime,
    event_type: str = EVENT_ACCESS_REJECTED,
    action: str = "",
    resource: str = "",
    scope_attempted: str | None = None,
    boundary_id: str | None = None,
    enforcing_principal: str | None = None,
    event_id: str | None = None,
    occurrence_count: int | None = None,
    first_seen_at: datetime | None = None,
    last_seen_at: datetime | None = None,
) -> AuditEvent:
    """Build an audit event for a request rejected BEFORE grant-scope evaluation.

    Per ADR 0008, security-relevant pre-grant rejections (e.g. an agent naming a
    grant that is not its own, or an operator over-issuing beyond an agent's
    bounds) are recorded for the operator, while the caller-facing response stays
    generic and leak-free. The event carries a coarse ``reason_code`` (also
    mirrored into ``reason`` so existing reason-keyed audit columns/queries keep
    working) and deliberately discloses no grant identifiers:
    ``grant_id``/``grant_ref`` are empty so the offending grant is never revealed
    in the trail. ``action``/``resource`` are retained as operator-only audit
    signal (they are not a caller leak). ``scope_attempted`` defaults to
    ``action:resource`` (the enforce case) but can be set explicitly (e.g. the
    requested scopes of an issuance). The authentication-failure path additionally
    carries an aggregated ``occurrence_count`` with the window's first/last-seen
    timestamps.
    """
    return AuditEvent(
        event_id=event_id or _new_event_id(),
        event_type=event_type,
        decision="deny",
        reason=reason_code,
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
        reason_code=reason_code,
        occurrence_count=occurrence_count,
        first_seen_at=first_seen_at,
        last_seen_at=last_seen_at,
    )


def _new_event_id() -> str:
    return f"evt_{token_urlsafe(12)}"
