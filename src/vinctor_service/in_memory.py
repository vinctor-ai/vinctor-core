from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from vinctor_core import (
    BoundaryRegistry,
    Grant,
    disable_boundary,
    enable_boundary,
    get_boundary_for_workspace,
    register_boundary,
)
from vinctor_core.models import AuditEvent, Boundary, BoundaryRegistrationInput
from vinctor_service.audit import InMemoryAuditWriter
from vinctor_service.auto_approval import (
    auto_approve_grant_request,
    create_auto_approval_rule,
    disable_auto_approval_rule,
    evaluate_auto_approval,
    list_auto_approval_rules,
)
from vinctor_service.grant_requests import (
    approve_grant_request,
    create_grant_request,
    list_grant_requests,
    lookup_grant_request,
    reject_grant_request,
)
from vinctor_service.grants import (
    InMemoryAgentIssuableScopeBoundsRepository,
    issue_grant,
    list_grants,
    lookup_grant,
    revoke_grant,
)
from vinctor_service.models import (
    AutoApprovalEvaluationResult,
    AutoApprovalRule,
    GrantIssueRequest,
    GrantIssueResult,
    GrantRequest,
    GrantRequestCreateRequest,
    GrantRequestCreateResult,
    GrantRequestDecisionResult,
    V1EnforceRequest,
    V1EnforceResponse,
)
from vinctor_service.repositories import (
    InMemoryAutoApprovalRuleRepository,
    InMemoryGrantRepository,
    InMemoryGrantRequestRepository,
)
from vinctor_service.v1_enforce import enforce_v1_contract


@dataclass
class InMemoryV1Service:
    grants: tuple[Grant, ...] = ()
    boundary_registry: BoundaryRegistry = field(default_factory=BoundaryRegistry)
    audit_writer: InMemoryAuditWriter = field(default_factory=InMemoryAuditWriter)
    initial_issuable_scope_bounds: dict[tuple[str, str], tuple[str, ...]] = field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        self.grant_repository = InMemoryGrantRepository(self.grants)
        self.grant_request_repository = InMemoryGrantRequestRepository()
        self.auto_approval_rule_repository = InMemoryAutoApprovalRuleRepository()
        self.scope_bounds_repository = InMemoryAgentIssuableScopeBoundsRepository(
            self.initial_issuable_scope_bounds
        )

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self.audit_writer.events)

    def get_audit_event(self, event_id: str) -> AuditEvent | None:
        return next(
            (event for event in self.audit_writer.events if event.event_id == event_id),
            None,
        )

    def register_boundary(
        self,
        registration: BoundaryRegistrationInput,
        *,
        now: datetime | None = None,
        boundary_id: str | None = None,
    ) -> Boundary:
        return register_boundary(
            self.boundary_registry,
            registration,
            now=now,
            boundary_id=boundary_id,
        )

    def get_boundary(self, *, boundary_id: str, workspace_id: str) -> Boundary | None:
        return get_boundary_for_workspace(
            self.boundary_registry,
            boundary_id,
            workspace_id,
        )

    def list_boundaries(self, workspace_id: str) -> tuple[Boundary, ...]:
        return tuple(self.boundary_registry.list_for_workspace(workspace_id))

    def disable_boundary(
        self,
        *,
        boundary_id: str,
        workspace_id: str,
        now: datetime | None = None,
    ) -> Boundary | None:
        return disable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
        )

    def enable_boundary(
        self,
        *,
        boundary_id: str,
        workspace_id: str,
        now: datetime | None = None,
    ) -> Boundary | None:
        return enable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
        )

    def set_agent_issuable_scope_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        now: datetime,
    ) -> None:
        self.scope_bounds_repository.set_bounds(
            workspace_id=workspace_id,
            agent_id=agent_id,
            scopes=scopes,
            now=now,
        )

    def issue_grant(
        self,
        request: GrantIssueRequest,
        *,
        now: datetime,
    ) -> GrantIssueResult:
        return issue_grant(
            request,
            grant_repository=self.grant_repository,
            scope_bounds_repository=self.scope_bounds_repository,
            audit_writer=self.audit_writer,
            now=now,
        )

    def lookup_grant(self, *, grant_ref: str, workspace_id: str) -> Grant | None:
        return lookup_grant(
            grant_ref=grant_ref,
            workspace_id=workspace_id,
            grant_repository=self.grant_repository,
        )

    def list_grants(
        self,
        *,
        workspace_id: str,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]:
        return list_grants(
            workspace_id=workspace_id,
            agent_id=agent_id,
            status=status,
            grant_repository=self.grant_repository,
        )

    def revoke_grant(
        self,
        *,
        grant_ref: str,
        workspace_id: str,
        now: datetime,
    ) -> tuple[Grant, str] | None:
        return revoke_grant(
            grant_ref=grant_ref,
            workspace_id=workspace_id,
            grant_repository=self.grant_repository,
            audit_writer=self.audit_writer,
            now=now,
        )

    def create_grant_request(
        self,
        request: GrantRequestCreateRequest,
        *,
        now: datetime,
    ) -> GrantRequestCreateResult:
        return create_grant_request(
            request,
            request_repository=self.grant_request_repository,
            audit_writer=self.audit_writer,
            now=now,
        )

    def lookup_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
    ) -> GrantRequest | None:
        return lookup_grant_request(
            request_id=request_id,
            workspace_id=workspace_id,
            request_repository=self.grant_request_repository,
        )

    def list_grant_requests(self, *, workspace_id: str) -> tuple[GrantRequest, ...]:
        return list_grant_requests(
            workspace_id=workspace_id,
            request_repository=self.grant_request_repository,
        )

    def approve_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        decision_reason: str | None,
        now: datetime,
    ) -> GrantRequestDecisionResult:
        return approve_grant_request(
            request_id=request_id,
            workspace_id=workspace_id,
            decided_by=decided_by,
            decision_reason=decision_reason,
            request_repository=self.grant_request_repository,
            grant_repository=self.grant_repository,
            scope_bounds_repository=self.scope_bounds_repository,
            audit_writer=self.audit_writer,
            now=now,
        )

    def reject_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        decision_reason: str | None,
        now: datetime,
    ) -> GrantRequestDecisionResult:
        return reject_grant_request(
            request_id=request_id,
            workspace_id=workspace_id,
            decided_by=decided_by,
            decision_reason=decision_reason,
            request_repository=self.grant_request_repository,
            audit_writer=self.audit_writer,
            now=now,
        )

    def create_auto_approval_rule(self, rule: AutoApprovalRule) -> AutoApprovalRule:
        return create_auto_approval_rule(
            rule_repository=self.auto_approval_rule_repository,
            rule=rule,
        )

    def list_auto_approval_rules(self, *, workspace_id: str) -> tuple[AutoApprovalRule, ...]:
        return list_auto_approval_rules(
            rule_repository=self.auto_approval_rule_repository,
            workspace_id=workspace_id,
        )

    def disable_auto_approval_rule(
        self,
        *,
        rule_id: str,
        workspace_id: str,
        disabled_by: str,
        now: datetime,
    ) -> AutoApprovalRule | None:
        return disable_auto_approval_rule(
            rule_repository=self.auto_approval_rule_repository,
            rule_id=rule_id,
            workspace_id=workspace_id,
            disabled_by=disabled_by,
            now=now,
        )

    def evaluate_auto_approval(
        self,
        *,
        request: GrantRequest,
    ) -> AutoApprovalEvaluationResult:
        return evaluate_auto_approval(
            request=request,
            rule_repository=self.auto_approval_rule_repository,
        )

    def auto_approve_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        now: datetime,
    ) -> GrantRequestDecisionResult:
        return auto_approve_grant_request(
            request_id=request_id,
            workspace_id=workspace_id,
            decided_by=decided_by,
            request_repository=self.grant_request_repository,
            rule_repository=self.auto_approval_rule_repository,
            grant_repository=self.grant_repository,
            scope_bounds_repository=self.scope_bounds_repository,
            audit_writer=self.audit_writer,
            now=now,
        )

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
        )
