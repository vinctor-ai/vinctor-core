from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from vinctor_core import BoundaryRegistry, Grant
from vinctor_core.models import AuditEvent
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

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
        )
