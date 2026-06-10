from __future__ import annotations

from typing import Protocol

from vinctor_core.models import AuditEvent


class AuditWriter(Protocol):
    def write(self, event: AuditEvent) -> None: ...


class InMemoryAuditWriter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)
