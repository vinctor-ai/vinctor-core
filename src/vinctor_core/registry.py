from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from secrets import token_urlsafe

from vinctor_core.models import Boundary, BoundaryRegistrationInput


@dataclass
class BoundaryRegistry:
    _boundaries: dict[str, Boundary] = field(default_factory=dict)

    def add(self, boundary: Boundary, *, operation: str = "register") -> Boundary:
        # Durable registries use the caller's operation to select their control
        # event. The pure registry intentionally has no auditor and ignores it.
        self._boundaries[boundary.boundary_id] = boundary
        return boundary

    def get(self, boundary_id: str) -> Boundary | None:
        return self._boundaries.get(boundary_id)

    def list_for_workspace(self, workspace_id: str) -> list[Boundary]:
        return [
            boundary
            for boundary in self._boundaries.values()
            if boundary.workspace_id == workspace_id
        ]


def register_boundary(
    registry: BoundaryRegistry,
    registration: BoundaryRegistrationInput,
    *,
    now: datetime | None = None,
    boundary_id: str | None = None,
) -> Boundary:
    if registration.mode != "fail_closed":
        raise ValueError("boundary mode must be fail_closed")
    if registration.status not in {"active", "disabled"}:
        raise ValueError("boundary status must be active or disabled")
    if _has_boundary_name(registry, registration.workspace_id, registration.name):
        raise ValueError("boundary name must be unique within workspace")

    timestamp = now or datetime.now(UTC)
    boundary = Boundary(
        boundary_id=boundary_id or _new_boundary_id(),
        workspace_id=registration.workspace_id,
        name=registration.name,
        runtime=registration.runtime,
        boundary_type=registration.boundary_type,
        mode=registration.mode,
        status=registration.status,
        created_at=timestamp,
        updated_at=timestamp,
    )
    # Registration intent wins even when a durable registry's boundary-id
    # upsert replaces an existing row: re-registration is still recorded as
    # one boundary_registered operation, not inferred from the prior row.
    return registry.add(boundary, operation="register")


def get_boundary_for_workspace(
    registry: BoundaryRegistry,
    boundary_id: str,
    workspace_id: str,
) -> Boundary | None:
    boundary = registry.get(boundary_id)
    if boundary is None or boundary.workspace_id != workspace_id:
        return None
    return boundary


def disable_boundary(
    registry: BoundaryRegistry,
    *,
    boundary_id: str,
    workspace_id: str,
    now: datetime | None = None,
) -> Boundary | None:
    boundary = get_boundary_for_workspace(registry, boundary_id, workspace_id)
    if boundary is None:
        return None

    disabled = boundary.with_status("disabled", updated_at=now or datetime.now(UTC))
    return registry.add(disabled, operation="disable")


def enable_boundary(
    registry: BoundaryRegistry,
    *,
    boundary_id: str,
    workspace_id: str,
    now: datetime | None = None,
) -> Boundary | None:
    boundary = get_boundary_for_workspace(registry, boundary_id, workspace_id)
    if boundary is None:
        return None
    if boundary.status == "active":
        return registry.add(boundary, operation="enable")

    enabled = boundary.with_status("active", updated_at=now or datetime.now(UTC))
    return registry.add(enabled, operation="enable")


def _new_boundary_id() -> str:
    return f"bnd_{token_urlsafe(12)}"


def _has_boundary_name(
    registry: BoundaryRegistry,
    workspace_id: str,
    name: str,
) -> bool:
    return any(
        boundary.name == name
        for boundary in registry.list_for_workspace(workspace_id)
    )
