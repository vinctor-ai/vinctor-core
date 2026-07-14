from __future__ import annotations

from datetime import datetime
from secrets import token_urlsafe

from vinctor_core.models import AuditEvent, BoundaryLookup
from vinctor_core.scope import (
    attempted_scope,
    is_valid_requested_action,
    is_valid_requested_resource,
)
from vinctor_service.audit import AuditWriter
from vinctor_service.models import V1ObserveRequest, V1ObserveResponse


def record_observation(
    request: V1ObserveRequest,
    *,
    audit_writer: AuditWriter,
    now: datetime,
    boundary_registry: BoundaryLookup | None = None,
) -> V1ObserveResponse:
    if request.classification == "mapped":
        if request.action is None or not is_valid_requested_action(request.action):
            return _invalid("action must be a valid Vinctor action")
        if request.resource is None or not is_valid_requested_resource(request.resource):
            return _invalid("resource must be a valid Vinctor resource")
        event_type = "action_observed"
        action = request.action
        resource = request.resource
        scope = attempted_scope(action, resource)
    elif request.classification == "unmapped":
        if request.action is not None or request.resource is not None:
            return _invalid("unmapped observations must not include action or resource")
        event_type = "action_unmapped"
        action = ""
        resource = ""
        scope = ""
    else:
        return _invalid("classification must be mapped or unmapped")

    boundary = (
        boundary_registry.get(request.boundary_id)
        if boundary_registry is not None and request.boundary_id is not None
        else None
    )
    if boundary is not None and boundary.workspace_id != request.workspace_id:
        boundary = None

    event = AuditEvent(
        event_id=_new_event_id(),
        event_type=event_type,
        decision="permit",
        reason="observe_mode",
        workspace_id=request.workspace_id,
        agent_id=request.agent_id,
        grant_id="",
        grant_ref="",
        action=action,
        resource=resource,
        scope_attempted=scope,
        scope_matched=None,
        boundary_id=request.boundary_id,
        runtime=boundary.runtime if boundary else None,
        boundary_type=boundary.boundary_type if boundary else None,
        created_at=now,
    )
    try:
        audit_writer.write(event)
    except Exception:
        return V1ObserveResponse(
            status_code=503,
            error="service_unavailable",
            reason="audit write failed; observation was not recorded",
        )
    return V1ObserveResponse(status_code=200, audit_event_id=event.event_id)


def _invalid(reason: str) -> V1ObserveResponse:
    return V1ObserveResponse(status_code=400, error="invalid_request", reason=reason)


def _new_event_id() -> str:
    return f"evt_{token_urlsafe(12)}"
