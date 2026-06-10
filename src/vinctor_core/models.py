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

    def to_dict(self) -> dict[str, str | None]:
        return {
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
