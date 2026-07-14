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

    def list_filtered(
        self,
        workspace_id: str,
        *,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        agent_id: str | None = None,
        request_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        identity_proven: bool | None = None,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]: ...

    def list_auth_failures(self, *, limit: int) -> tuple[AuditEvent, ...]: ...


WorkspaceIdentityResolver = Callable[[str, datetime], WorkspaceIdentity | None]
ServiceOperatorResolver = Callable[[str, datetime], bool]


@dataclass(frozen=True)
class AuditEventFilters:
    agent_id: str | None = None
    event_type: str | None = None
    grant_ref: str | None = None
    boundary_id: str | None = None
    request_id: str | None = None
    reason_code: str | None = None
    enforcing_principal: str | None = None
    # Tri-state: None = no filter, True/False = match that value.
    identity_proven: bool | None = None
    limit: int = 20


def handle_v1_audit_events_http(
    *,
    method: str,
    path: str,
    query_string: str,
    headers: Mapping[str, str],
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    auditor_identities: Mapping[str, WorkspaceIdentity] | None = None,
    auditor_identity_resolver: WorkspaceIdentityResolver | None = None,
    service: AuditReadService,
    now: datetime,
) -> V1HttpResponse:
    identity = _audit_identity(
        headers,
        workspace_identities=workspace_identities,
        workspace_identity_resolver=workspace_identity_resolver,
        auditor_identities=auditor_identities,
        auditor_identity_resolver=auditor_identity_resolver,
        now=now,
    )
    if identity is None:
        return _error(
            401,
            "authentication_required",
            "valid X-Workspace-Key or X-Auditor-Key header is required",
        )

    if path == "/v1/audit-events":
        if method != "GET":
            return _error(405, "method_not_allowed", "GET is required for /v1/audit-events")
        filters = _parse_filters(query_string)
        if isinstance(filters, V1HttpResponse):
            return filters
        events = service.list_filtered(
            identity.workspace_id,
            event_type=filters.event_type,
            grant_ref=filters.grant_ref,
            boundary_id=filters.boundary_id,
            agent_id=filters.agent_id,
            request_id=filters.request_id,
            reason_code=filters.reason_code,
            enforcing_principal=filters.enforcing_principal,
            identity_proven=filters.identity_proven,
            limit=filters.limit,
        )
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


def handle_v1_service_auth_failures_http(
    *,
    method: str,
    path: str,
    query_string: str,
    headers: Mapping[str, str],
    service_operator_keys: set[str] | None = None,
    service_operator_resolver: ServiceOperatorResolver | None = None,
    service: AuditReadService,
    now: datetime,
) -> V1HttpResponse:
    normalized = {key.lower(): value for key, value in headers.items()}
    raw_key = normalized.get("x-service-operator-key")
    authenticated = False
    if raw_key is not None:
        authenticated = (
            service_operator_resolver(raw_key, now)
            if service_operator_resolver is not None
            else raw_key in (service_operator_keys or set())
        )
    if not authenticated:
        return _error(
            401,
            "authentication_required",
            "valid X-Service-Operator-Key header is required",
        )
    if path != "/v1/service/audit/auth-failures":
        return _error(404, "not_found", "route not found")
    if method != "GET":
        return _error(405, "method_not_allowed", "GET is required")
    params = parse_qs(query_string, keep_blank_values=True)
    if set(params) - {"limit"}:
        return _error(400, "invalid_request", "only limit is supported")
    try:
        limit = int(params.get("limit", ["20"])[0])
    except ValueError:
        return _error(400, "invalid_request", "limit must be an integer")
    if limit <= 0 or limit > 200:
        return _error(400, "invalid_request", "limit must be between 1 and 200")
    events = service.list_auth_failures(limit=limit)
    return V1HttpResponse(
        status_code=200,
        body={"auth_failures": [_audit_event_body(event) for event in events]},
    )


def _audit_identity(
    headers: Mapping[str, str],
    *,
    workspace_identities: Mapping[str, WorkspaceIdentity] | None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None,
    auditor_identities: Mapping[str, WorkspaceIdentity] | None,
    auditor_identity_resolver: WorkspaceIdentityResolver | None,
    now: datetime,
) -> WorkspaceIdentity | None:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    workspace_key = normalized_headers.get("x-workspace-key")
    if workspace_key is not None:
        if workspace_identity_resolver is not None:
            return workspace_identity_resolver(workspace_key, now)
        return (workspace_identities or {}).get(workspace_key)
    auditor_key = normalized_headers.get("x-auditor-key")
    if auditor_key is None:
        return None
    if auditor_identity_resolver is not None:
        return auditor_identity_resolver(auditor_key, now)
    return (auditor_identities or {}).get(auditor_key)


def _parse_filters(query_string: str) -> AuditEventFilters | V1HttpResponse:
    params = parse_qs(query_string, keep_blank_values=True)
    allowed = {
        "agent_id",
        "event_type",
        "grant_ref",
        "boundary_id",
        "request_id",
        "reason_code",
        "enforcing_principal",
        "identity_proven",
        "limit",
    }
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

    identity_proven: bool | None = None
    if values["identity_proven"] is not None:
        normalized = values["identity_proven"].strip().lower()
        if normalized == "true":
            identity_proven = True
        elif normalized == "false":
            identity_proven = False
        else:
            return _error(400, "invalid_request", "identity_proven must be true or false")

    return AuditEventFilters(
        agent_id=values["agent_id"],
        event_type=values["event_type"],
        grant_ref=values["grant_ref"],
        boundary_id=values["boundary_id"],
        request_id=values["request_id"],
        reason_code=values["reason_code"],
        enforcing_principal=values["enforcing_principal"],
        identity_proven=identity_proven,
        limit=limit,
    )


def _audit_event_body(event: AuditEvent) -> dict[str, str | bool | int | None]:
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
        "enforcing_principal": event.enforcing_principal,
        "reason_code": event.reason_code,
        "occurrence_count": event.occurrence_count,
        "first_seen_at": (
            event.first_seen_at.isoformat() if event.first_seen_at is not None else None
        ),
        "last_seen_at": (
            event.last_seen_at.isoformat() if event.last_seen_at is not None else None
        ),
        "identity_proven": event.identity_proven,
        "token_id": event.token_id,
    }


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})
