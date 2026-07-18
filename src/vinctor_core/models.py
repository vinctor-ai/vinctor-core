from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

Decision = Literal["permit", "deny"]
BoundaryMode = Literal["fail_closed"]
BoundaryStatus = Literal["active", "disabled"]


@dataclass
class Grant:
    grant_id: str
    grant_ref: str
    workspace_id: str
    agent_id: str
    scopes: tuple[str, ...]
    status: str
    expires_at: datetime | None = None


@dataclass(frozen=True)
class Boundary:
    boundary_id: str
    workspace_id: str
    name: str
    runtime: str
    boundary_type: str
    mode: BoundaryMode
    status: BoundaryStatus
    created_at: datetime
    updated_at: datetime

    def with_status(self, status: BoundaryStatus, *, updated_at: datetime) -> Boundary:
        return Boundary(
            boundary_id=self.boundary_id,
            workspace_id=self.workspace_id,
            name=self.name,
            runtime=self.runtime,
            boundary_type=self.boundary_type,
            mode=self.mode,
            status=status,
            created_at=self.created_at,
            updated_at=updated_at,
        )


@dataclass(frozen=True)
class BoundaryRegistrationInput:
    workspace_id: str
    name: str
    runtime: str
    boundary_type: str
    mode: BoundaryMode = "fail_closed"
    status: BoundaryStatus = "active"


class BoundaryLookup(Protocol):
    def get(self, boundary_id: str) -> Boundary | None: ...


@dataclass(frozen=True)
class EnforceInput:
    grant: Grant
    action: str
    resource: str
    now: datetime
    boundary_id: str | None = None
    boundary_registry: BoundaryLookup | None = None
    require_boundary: bool = False


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reason: str
    grant_id: str
    grant_ref: str
    workspace_id: str
    agent_id: str
    action: str
    resource: str
    scope_attempted: str
    scope_matched: str | None
    boundary: Boundary | None = None
    attempted_boundary_id: str | None = None


@dataclass(frozen=True)
class PolicyInput:
    workspace_id: str
    agent_id: str
    grants: tuple[Grant, ...]
    action: str
    resource: str
    now: datetime
    boundary_id: str | None = None
    boundary_registry: BoundaryLookup | None = None


@dataclass(frozen=True)
class PolicyResult:
    decision: Decision
    reason: str
    workspace_id: str
    agent_id: str
    action: str
    resource: str
    scope_attempted: str
    scope_matched: str | None
    grant_id: str | None = None
    grant_ref: str | None = None
    enforce_result: DecisionResult | None = None


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    event_type: str
    decision: Decision
    reason: str
    workspace_id: str
    agent_id: str
    grant_id: str
    grant_ref: str
    action: str
    resource: str
    scope_attempted: str
    scope_matched: str | None
    boundary_id: str | None
    runtime: str | None
    boundary_type: str | None
    created_at: datetime
    enforcing_principal: str | None = None
    # Pre-grant-evaluation rejection fields (ADR 0008). Absent on decision and
    # grant-lifecycle events; set only on operator-only rejection events.
    reason_code: str | None = None
    occurrence_count: int | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    # ADR 0007 Model 2 identity-proof (set only on a proven delegated decision).
    identity_proven: bool = False
    token_id: str | None = None
    # ADR 0019: event category on the shared chain — "decision" (what an agent
    # did or asked for) or "control" (an operator changed the rules). Enables
    # per-category export/retention/access WITHOUT splitting the chain.
    event_class: str = "decision"

    def to_dict(self) -> dict[str, object]:
        event: dict[str, object] = {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "decision": self.decision,
            "reason": self.reason,
            "workspace_id": self.workspace_id,
            "agent_id": self.agent_id,
            "grant_id": self.grant_id,
            "grant_ref": self.grant_ref,
            "action": self.action,
            "resource": self.resource,
            "scope_attempted": self.scope_attempted,
            "scope_matched": self.scope_matched,
            "boundary_id": self.boundary_id,
            "runtime": self.runtime,
            "boundary_type": self.boundary_type,
            "created_at": self.created_at.isoformat(),
        }
        if self.enforcing_principal is not None:
            event["enforcing_principal"] = self.enforcing_principal
        if self.reason_code is not None:
            event["reason_code"] = self.reason_code
        if self.occurrence_count is not None:
            event["occurrence_count"] = self.occurrence_count
        if self.first_seen_at is not None:
            event["first_seen_at"] = self.first_seen_at.isoformat()
        if self.last_seen_at is not None:
            event["last_seen_at"] = self.last_seen_at.isoformat()
        if self.identity_proven:
            event["identity_proven"] = True
        if self.token_id is not None:
            event["token_id"] = self.token_id
        # Omit-when-default (like identity_proven): an absent key reads as
        # "decision", so pre-event_class rows and new decision rows share one
        # canonical form and decision-event JSON stays byte-identical.
        if self.event_class != "decision":
            event["event_class"] = self.event_class
        return event
