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
from vinctor_service.grants import (
    InMemoryAgentIssuableScopeBoundsRepository,
    issue_grant,
    lookup_grant,
    revoke_grant,
)
from vinctor_service.models import (
    GrantIssueRequest,
    GrantIssueResult,
    V1EnforceRequest,
    V1EnforceResponse,
)
from vinctor_service.repositories import InMemoryGrantRepository
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
        self.scope_bounds_repository = InMemoryAgentIssuableScopeBoundsRepository(
            self.initial_issuable_scope_bounds
        )

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self.audit_writer.events)

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

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
        )
