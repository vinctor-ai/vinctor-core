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
from vinctor_service.models import V1EnforceRequest, V1EnforceResponse
from vinctor_service.repositories import InMemoryGrantRepository
from vinctor_service.v1_enforce import enforce_v1_contract


@dataclass
class InMemoryV1Service:
    grants: tuple[Grant, ...] = ()
    boundary_registry: BoundaryRegistry = field(default_factory=BoundaryRegistry)
    audit_writer: InMemoryAuditWriter = field(default_factory=InMemoryAuditWriter)

    def __post_init__(self) -> None:
        self.grant_repository = InMemoryGrantRepository(self.grants)

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

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
        )
