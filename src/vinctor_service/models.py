from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from vinctor_core.models import Decision, Grant

GrantIssueStatus = Literal["issued", "rejected"]
GrantRequestStatus = Literal["pending", "approved", "rejected", "cancelled", "expired"]
GrantRequestCreateStatus = Literal["created", "rejected"]
GrantRequestDecisionStatus = Literal["approved", "rejected", "failed"]
GrantRequestRoutingHint = Literal[
    "pending_review",
    "auto_approval_available",
    "manual_review_required",
]
ApprovalRuleStatus = Literal["active", "disabled"]
AutoApprovalEvaluationDecision = Literal["would_approve", "would_not_approve"]


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
class V1DelegatedEnforceRequest:
    """An on-behalf-of enforce request from a Policy Enforcement Point (PEP).

    The PEP authenticates with its own key (``pep_id`` / ``pep_workspace_id``)
    and asserts the subject it is asking about (``workspace_id`` / ``agent_id``).
    See ADR 0007. The subject identity proof model is an open decision; this
    request only carries the asserted subject, not a proof of it.
    """

    pep_id: str
    workspace_id: str
    agent_id: str
    grant_ref: str
    action: str
    resource: str
    boundary_id: str | None = None
    pep_workspace_id: str | None = None


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
    ttl_seconds: int = 0
    grant_id: str | None = None
    grant_ref: str | None = None


@dataclass(frozen=True)
class GrantIssueResult:
    status: GrantIssueStatus
    reason: str
    grant: Grant | None = None
    audit_event_id: str | None = None


@dataclass(frozen=True)
class GrantRequest:
    request_id: str
    workspace_id: str
    requester_agent_id: str
    target_agent_id: str
    requested_scopes: tuple[str, ...]
    requested_ttl_seconds: int
    reason: str
    status: GrantRequestStatus
    created_at: datetime
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
    issued_grant_ref: str | None = None
    task_id: str | None = None
    session_id: str | None = None
    boundary_id: str | None = None
    requester_runtime: str | None = None
    repo: str | None = None
    worktree: str | None = None


@dataclass(frozen=True)
class GrantRequestCreateRequest:
    workspace_id: str
    requester_agent_id: str
    requested_scopes: tuple[str, ...]
    requested_ttl_seconds: int
    reason: str
    target_agent_id: str | None = None
    request_id: str | None = None
    task_id: str | None = None
    session_id: str | None = None
    boundary_id: str | None = None
    requester_runtime: str | None = None
    repo: str | None = None
    worktree: str | None = None


@dataclass(frozen=True)
class GrantRequestCreateResult:
    status: GrantRequestCreateStatus
    reason: str
    request: GrantRequest | None = None
    audit_event_id: str | None = None


@dataclass(frozen=True)
class GrantRequestDecisionResult:
    status: GrantRequestDecisionStatus
    reason: str
    request: GrantRequest | None = None
    grant: Grant | None = None
    audit_event_id: str | None = None
    auto_approval_rule_id: str | None = None


@dataclass(frozen=True)
class AutoApprovalRule:
    rule_id: str
    workspace_id: str
    name: str
    target_agent_id: str
    allowed_scopes: tuple[str, ...]
    max_ttl_seconds: int
    status: ApprovalRuleStatus
    created_by: str
    created_at: datetime
    updated_by: str | None = None
    updated_at: datetime | None = None


@dataclass(frozen=True)
class AutoApprovalEvaluationResult:
    decision: AutoApprovalEvaluationDecision
    reason: str
    request: GrantRequest
    rule: AutoApprovalRule | None = None
