from __future__ import annotations

from dataclasses import dataclass

from vinctor_core.models import Decision


@dataclass(frozen=True)
class AuthorizationRequest:
    workspace_id: str
    agent_id: str
    action: str
    resource: str
    boundary_id: str | None = None


@dataclass(frozen=True)
class AuthorizationResponse:
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
    boundary_id: str | None = None
