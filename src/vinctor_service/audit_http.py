from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from urllib.parse import parse_qs

from vinctor_core.models import AuditEvent
from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.v1_http import V1HttpResponse


class AuditReadService(Protocol):
    @property
    def audit_events(self) -> tuple[AuditEvent, ...]: ...

    def get_audit_event(self, event_id: str) -> AuditEvent | None: ...


WorkspaceIdentityResolver = Callable[[str, datetime], WorkspaceIdentity | None]


@dataclass(frozen=True)
class AuditEventFilters:
    event_type: str | None = None
    grant_ref: str | None = None
    boundary_id: str | None = None
    request_id: str | None = None
    limit: int = 20


def handle_v1_audit_events_http(
    *,
    method: str,
    path: str,
    query_string: str,
    headers: Mapping[str, str],
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    service: AuditReadService,
    now: datetime,
) -> V1HttpResponse:
    identity = _workspace_identity(
        headers,
        workspace_identities=workspace_identities,
        workspace_identity_resolver=workspace_identity_resolver,
        now=now,
    )
    if identity is None:
        return _error(401, "authentication_required", "valid X-Workspace-Key header is required")

    if path == "/v1/audit-events":
        if method != "GET":
            return _error(405, "method_not_allowed", "GET is required for /v1/audit-events")
        filters = _parse_filters(query_string)
        if isinstance(filters, V1HttpResponse):
            return filters
        events = [
            event
            for event in service.audit_events
            if event.workspace_id == identity.workspace_id and _event_matches(event, filters)
        ][-filters.limit :]
        return V1HttpResponse(
            status_code=200,
            body={"audit_events": [_audit_event_body(event) for event in events]},
        )

    prefix = "/v1/audit-events/"
    if path.startswith(prefix):
        event_id = path.removeprefix(prefix)
        if event_id == "" or "/" in event_id:
            return _error(404, "not_found", "route not found")
        if method != "GET":
            return _error(
                405,
                "method_not_allowed",
                "GET is required for /v1/audit-events/{event_id}",
            )
        event = service.get_audit_event(event_id)
        if event is None or event.workspace_id != identity.workspace_id:
            return _error(404, "audit_event_not_found", "audit event was not found")
        return V1HttpResponse(status_code=200, body=_audit_event_body(event))

    return _error(404, "not_found", "route not found")


def _workspace_identity(
    headers: Mapping[str, str],
    *,
    workspace_identities: Mapping[str, WorkspaceIdentity] | None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None,
    now: datetime,
) -> WorkspaceIdentity | None:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    workspace_key = normalized_headers.get("x-workspace-key")
    if workspace_key is None:
        return None
    if workspace_identity_resolver is not None:
        return workspace_identity_resolver(workspace_key, now)
    return (workspace_identities or {}).get(workspace_key)


def _parse_filters(query_string: str) -> AuditEventFilters | V1HttpResponse:
    params = parse_qs(query_string, keep_blank_values=True)
    allowed = {"event_type", "grant_ref", "boundary_id", "request_id", "limit"}
    extra = sorted(set(params) - allowed)
    if extra:
        return _error(400, "invalid_request", f"unexpected query parameter: {extra[0]}")

    values: dict[str, str | None] = {}
    for key in allowed:
        parsed = params.get(key)
        if parsed is None:
            values[key] = None
            continue
        if len(parsed) != 1 or parsed[0] == "":
            return _error(400, "invalid_request", f"{key} must be a single non-empty value")
        values[key] = parsed[0]

    limit = 20
    if values["limit"] is not None:
        try:
            limit = int(values["limit"])
        except ValueError:
            return _error(400, "invalid_request", "limit must be a positive integer")
        if limit <= 0 or limit > 100:
            return _error(400, "invalid_request", "limit must be between 1 and 100")

    return AuditEventFilters(
        event_type=values["event_type"],
        grant_ref=values["grant_ref"],
        boundary_id=values["boundary_id"],
        request_id=values["request_id"],
        limit=limit,
    )


def _event_matches(event: AuditEvent, filters: AuditEventFilters) -> bool:
    if filters.event_type is not None and event.event_type != filters.event_type:
        return False
    if filters.grant_ref is not None and event.grant_ref != filters.grant_ref:
        return False
    if filters.boundary_id is not None and event.boundary_id != filters.boundary_id:
        return False
    return filters.request_id is None or _matches_request_id(event, filters.request_id)


def _matches_request_id(event: AuditEvent, request_id: str) -> bool:
    return event.resource == f"grant_request/{request_id}" or event.grant_ref == request_id


def _audit_event_body(event: AuditEvent) -> dict[str, str | None]:
    return {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "decision": event.decision,
        "reason": event.reason,
        "workspace_id": event.workspace_id,
        "agent_id": event.agent_id,
        "grant_id": event.grant_id,
        "grant_ref": event.grant_ref,
        "action": event.action,
        "resource": event.resource,
        "scope_attempted": event.scope_attempted,
        "scope_matched": event.scope_matched,
        "boundary_id": event.boundary_id,
        "runtime": event.runtime,
        "boundary_type": event.boundary_type,
        "created_at": event.created_at.isoformat(),
    }


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})
