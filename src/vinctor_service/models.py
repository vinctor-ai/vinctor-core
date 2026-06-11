from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from vinctor_core.models import Decision, Grant

GrantIssueStatus = Literal["issued", "rejected"]


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


@dataclass(frozen=True)
class V1EnforceRequest:
    workspace_id: str
    agent_id: str
    grant_ref: str
    action: str
    resource: str
    boundary_id: str | None = None


@dataclass(frozen=True)
class V1EnforceResponse:
    status_code: int
    decision: Decision | None = None
    error: str | None = None
    reason: str | None = None
    grant_id: str | None = None
    agent_id: str | None = None
    scope_matched: str | None = None
    audit_event_id: str | None = None


@dataclass(frozen=True)
class GrantIssueRequest:
    workspace_id: str
    target_agent_id: str
    requested_scopes: tuple[str, ...]
    ttl_seconds: int
    grant_id: str | None = None
    grant_ref: str | None = None


@dataclass(frozen=True)
class GrantIssueResult:
    status: GrantIssueStatus
    reason: str
    grant: Grant | None = None
    audit_event_id: str | None = None
