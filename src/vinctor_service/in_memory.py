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
from vinctor_core.audit import validate_audit_event_class
from vinctor_core.models import AuditEvent, Boundary, BoundaryRegistrationInput
from vinctor_service.audit import AuthFailureAuditThrottle, InMemoryAuditWriter
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
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
    V1EnforceResponse,
    V1ObserveRequest,
    V1ObserveResponse,
    V1SimulateRequest,
    V1SimulateResponse,
)
from vinctor_service.observations import record_observation
from vinctor_service.pop import PopReplayCache
from vinctor_service.repositories import (
    InMemoryAgentEnforcementSettingsRepository,
    InMemoryAutoApprovalRuleRepository,
    InMemoryGrantRepository,
    InMemoryGrantRequestRepository,
    InMemorySubjectTokenRepository,
)
from vinctor_service.service_config import DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS
from vinctor_service.simulations import simulate_v1_contract
from vinctor_service.v1_enforce import delegated_enforce_v1_contract, enforce_v1_contract


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
        self.subject_token_repository = InMemorySubjectTokenRepository()
        self.agent_enforcement_settings_repository = (
            InMemoryAgentEnforcementSettingsRepository()
        )
        self.scope_bounds_repository = InMemoryAgentIssuableScopeBoundsRepository(
            self.initial_issuable_scope_bounds
        )
        self._auth_failures = AuthFailureAuditThrottle()
        self._pop_replay = PopReplayCache()

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self.audit_writer.events)

    def get_audit_event(self, event_id: str) -> AuditEvent | None:
        return next(
            (event for event in self.audit_writer.events if event.event_id == event_id),
            None,
        )

    def list_filtered(
        self,
        workspace_id: str,
        *,
        event_class: str | None = None,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        agent_id: str | None = None,
        request_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        subject_token_verified: bool | None = None,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        """Workspace-scoped audit filter; reference impl for the SQLite pushdown.

        Same WHERE semantics + ordering as :meth:`SQLiteV1Service.list_filtered`:
        events are kept in insertion order and the most-recent ``limit`` are
        returned (the legacy ``[-limit:]`` slice), oldest-first within that
        window. Workspace scoping is mandatory. ``limit=None`` returns all matches.
        """
        validate_audit_event_class(event_class)
        matched = [
            event
            for event in self.audit_writer.events
            if event.workspace_id == workspace_id
            and _audit_event_matches(
                event,
                event_class=event_class,
                event_type=event_type,
                grant_ref=grant_ref,
                boundary_id=boundary_id,
                agent_id=agent_id,
                request_id=request_id,
                reason_code=reason_code,
                enforcing_principal=enforcing_principal,
                subject_token_verified=subject_token_verified,
            )
        ]
        if limit is not None:
            matched = matched[-limit:]
        return tuple(matched)

    def record_auth_failure(self, *, surface: str, now: datetime) -> None:
        self._auth_failures.record(self.audit_writer, surface=surface, now=now)

    def register_boundary(
        self,
        registration: BoundaryRegistrationInput,
        *,
        now: datetime | None = None,
        boundary_id: str | None = None,
        enforcing_principal: str | None = None,
    ) -> Boundary:
        return register_boundary(
            self.boundary_registry,
            registration,
            now=now,
            boundary_id=boundary_id,
            enforcing_principal=enforcing_principal,
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
        enforcing_principal: str | None = None,
    ) -> Boundary | None:
        return disable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
            enforcing_principal=enforcing_principal,
        )

    def enable_boundary(
        self,
        *,
        boundary_id: str,
        workspace_id: str,
        now: datetime | None = None,
        enforcing_principal: str | None = None,
    ) -> Boundary | None:
        return enable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
            enforcing_principal=enforcing_principal,
        )

    def set_agent_issuable_scope_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        now: datetime,
        enforcing_principal: str | None = None,
    ) -> None:
        self.scope_bounds_repository.set_bounds(
            workspace_id=workspace_id,
            agent_id=agent_id,
            scopes=scopes,
            max_ttl_seconds=max_ttl_seconds,
            now=now,
            enforcing_principal=enforcing_principal,
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

    def mint_subject_token(
        self, *, workspace_id, agent_id, grant_ref, audience, ttl_seconds, now,
        bound_action=None, bound_resource=None, pop=False,
    ):
        from vinctor_service.subject_tokens import mint_subject_token

        return mint_subject_token(
            grant_repository=self.grant_repository,
            subject_token_repository=self.subject_token_repository,
            audit_writer=self.audit_writer,
            workspace_id=workspace_id, agent_id=agent_id, grant_ref=grant_ref,
            audience=audience, ttl_seconds=ttl_seconds, now=now,
            bound_action=bound_action, bound_resource=bound_resource, pop=pop,
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
            agent_enforcement_settings_repository=self.agent_enforcement_settings_repository,
        )

    def observe(self, request: V1ObserveRequest, *, now: datetime) -> V1ObserveResponse:
        return record_observation(
            request,
            audit_writer=self.audit_writer,
            now=now,
            boundary_registry=self.boundary_registry,
        )

    def simulate(self, request: V1SimulateRequest, *, now: datetime) -> V1SimulateResponse:
        return simulate_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
            agent_enforcement_settings_repository=self.agent_enforcement_settings_repository,
        )

    def delegated_enforce(
        self,
        request: V1DelegatedEnforceRequest,
        *,
        now: datetime,
        pep_workspace_id: str | None = None,
        pop_skew_seconds: int = DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS,
    ) -> V1EnforceResponse:
        # ``pep_workspace_id`` is the TRUSTED workspace derived from the
        # authenticated PEP key (see handle_v1_delegated_enforce_http). Without
        # it the contract fails closed.
        return delegated_enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
            pep_workspace_id=pep_workspace_id,
            subject_token_repository=self.subject_token_repository,
            agent_enforcement_settings_repository=self.agent_enforcement_settings_repository,
            pop_replay_cache=self._pop_replay,
            pop_skew_seconds=pop_skew_seconds,
        )


def _audit_event_matches(
    event: AuditEvent,
    *,
    event_class: str | None,
    event_type: str | None,
    grant_ref: str | None,
    boundary_id: str | None,
    agent_id: str | None,
    request_id: str | None,
    reason_code: str | None = None,
    enforcing_principal: str | None = None,
    subject_token_verified: bool | None = None,
) -> bool:
    if event_class is not None and event.event_class != event_class:
        return False
    if agent_id is not None and event.agent_id != agent_id:
        return False
    if event_type is not None and event.event_type != event_type:
        return False
    if grant_ref is not None and event.grant_ref != grant_ref:
        return False
    if boundary_id is not None and event.boundary_id != boundary_id:
        return False
    if reason_code is not None and event.reason_code != reason_code:
        return False
    if enforcing_principal is not None and event.enforcing_principal != enforcing_principal:
        return False
    if (
        subject_token_verified is not None
        and event.subject_token_verified != subject_token_verified
    ):
        return False
    if request_id is None:
        return True
    return (
        event.resource == f"grant_request/{request_id}" or event.grant_ref == request_id
    )
