from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from vinctor_core.models import Grant
from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.models import GrantIssueRequest, GrantIssueResult
from vinctor_service.v1_http import V1HttpResponse


class GrantLifecycleService(Protocol):
    def issue_grant(
        self,
        request: GrantIssueRequest,
        *,
        now: datetime,
    ) -> GrantIssueResult: ...

    def lookup_grant(self, *, grant_ref: str, workspace_id: str) -> Grant | None: ...

    def revoke_grant(
        self,
        *,
        grant_ref: str,
        workspace_id: str,
        now: datetime,
    ) -> tuple[Grant, str] | None: ...


WorkspaceIdentityResolver = Callable[[str, datetime], WorkspaceIdentity | None]


@dataclass(frozen=True)
class ParsedGrantIssueBody:
    agent_id: str
    scopes: tuple[str, ...]
    ttl_seconds: int


def handle_v1_grants_http(
    *,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: object,
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    service: GrantLifecycleService,
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

    if path == "/v1/grants":
        if method != "POST":
            return _error(405, "method_not_allowed", "POST is required for /v1/grants")
        return _issue_grant(body, identity=identity, service=service, now=now)

    prefix = "/v1/grants/"
    if path.startswith(prefix):
        suffix = path.removeprefix(prefix)
        parts = suffix.split("/")
        if len(parts) == 1 and parts[0] != "":
            if method != "GET":
                return _error(
                    405,
                    "method_not_allowed",
                    "GET is required for /v1/grants/{grant_ref}",
                )
            grant = service.lookup_grant(
                grant_ref=parts[0],
                workspace_id=identity.workspace_id,
            )
            if grant is None:
                return _error(404, "grant_not_found", "grant was not found")
            return V1HttpResponse(status_code=200, body=_grant_body(grant))

        if len(parts) == 2 and parts[0] != "" and parts[1] == "revoke":
            if method != "POST":
                return _error(
                    405,
                    "method_not_allowed",
                    "POST is required for /v1/grants/{grant_ref}/revoke",
                )
            revoked = service.revoke_grant(
                grant_ref=parts[0],
                workspace_id=identity.workspace_id,
                now=now,
            )
            if revoked is None:
                return _error(404, "grant_not_found", "grant was not found")
            grant, audit_event_id = revoked
            return V1HttpResponse(
                status_code=200,
                body={**_grant_body(grant), "audit_event_id": audit_event_id},
            )

        if suffix == "" or "/" in suffix:
            return _error(404, "not_found", "route not found")

    return _error(404, "not_found", "route not found")


def _issue_grant(
    body: object,
    *,
    identity: WorkspaceIdentity,
    service: GrantLifecycleService,
    now: datetime,
) -> V1HttpResponse:
    parsed = _parse_issue_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    result = service.issue_grant(
        GrantIssueRequest(
            workspace_id=identity.workspace_id,
            target_agent_id=parsed.agent_id,
            requested_scopes=parsed.scopes,
            ttl_seconds=parsed.ttl_seconds,
        ),
        now=now,
    )
    if result.status == "rejected":
        status_code = 400 if result.reason in _BAD_REQUEST_REASONS else 403
        return _error(status_code, result.reason, result.reason)
    if result.grant is None:
        return _error(503, "service_unavailable", "grant issuance failed")

    return V1HttpResponse(
        status_code=201,
        body={**_grant_body(result.grant), "audit_event_id": result.audit_event_id},
    )


def _parse_issue_body(body: object) -> ParsedGrantIssueBody | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")

    required_fields = {"agent_id", "scopes", "ttl_seconds"}
    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields)
    if missing:
        return _error(400, "invalid_request", f"missing required field: {missing[0]}")
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")

    agent_id = body["agent_id"]
    if not isinstance(agent_id, str) or agent_id == "":
        return _error(400, "invalid_request", "agent_id must be a non-empty string")

    scopes = body["scopes"]
    if not isinstance(scopes, list) or not scopes:
        return _error(400, "invalid_request", "scopes must be a non-empty array")
    if any(not isinstance(scope, str) or scope == "" for scope in scopes):
        return _error(400, "invalid_request", "scopes must contain only non-empty strings")

    ttl_seconds = body["ttl_seconds"]
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        return _error(400, "invalid_request", "ttl_seconds must be a positive integer")

    return ParsedGrantIssueBody(
        agent_id=agent_id,
        scopes=tuple(scopes),
        ttl_seconds=ttl_seconds,
    )


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


def _grant_body(grant: Grant) -> dict[str, object]:
    return {
        "grant_id": grant.grant_id,
        "grant_ref": grant.grant_ref,
        "workspace_id": grant.workspace_id,
        "agent_id": grant.agent_id,
        "scopes": list(grant.scopes),
        "status": grant.status,
        "expires_at": grant.expires_at.isoformat() if grant.expires_at is not None else None,
    }


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})


_BAD_REQUEST_REASONS = {
    "invalid_workspace_id",
    "invalid_agent_id",
    "invalid_ttl",
    "missing_requested_scopes",
    "invalid_requested_scope",
    "invalid_issuable_scope_bound",
    "duplicate_grant_ref",
}
