from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from urllib.parse import parse_qs

from vinctor_core.models import Grant
from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.grant_http_responses import (
    BAD_GRANT_REQUEST_REASONS,
)
from vinctor_service.grant_http_responses import (
    error_response as _error,
)
from vinctor_service.grant_http_responses import (
    grant_body as _grant_body,
)
from vinctor_service.grant_issue_http import (
    ParsedGrantIssueBody as _ParsedGrantIssueBody,
)
from vinctor_service.grant_issue_http import (
    issue_v1_grant_response,
    parse_v1_grant_issue_body,
)
from vinctor_service.models import GrantIssueRequest, GrantIssueResult
from vinctor_service.v1_http import V1HttpResponse

ParsedGrantIssueBody = _ParsedGrantIssueBody
_BAD_REQUEST_REASONS = BAD_GRANT_REQUEST_REASONS


class GrantLifecycleService(Protocol):
    def issue_grant(
        self,
        request: GrantIssueRequest,
        *,
        now: datetime,
    ) -> GrantIssueResult: ...

    def lookup_grant(self, *, grant_ref: str, workspace_id: str) -> Grant | None: ...

    def list_grants(
        self,
        *,
        workspace_id: str,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]: ...

    def revoke_grant(
        self,
        *,
        grant_ref: str,
        workspace_id: str,
        now: datetime,
    ) -> tuple[Grant, str] | None: ...


WorkspaceIdentityResolver = Callable[[str, datetime], WorkspaceIdentity | None]


@dataclass(frozen=True, slots=True)
class ParsedGrantListFilters:
    agent_id: str | None = None
    status: str | None = None


def handle_v1_grants_http(
    *,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: object,
    query_string: str = "",
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
        if method == "GET":
            filters = _parse_list_filters(query_string)
            if isinstance(filters, V1HttpResponse):
                return filters
            grants = service.list_grants(
                workspace_id=identity.workspace_id,
                agent_id=filters.agent_id,
                status=filters.status,
            )
            return V1HttpResponse(
                status_code=200,
                body={"grants": [_grant_body(grant) for grant in grants]},
            )
        if method != "POST":
            return _error(
                405,
                "method_not_allowed",
                "GET or POST is required for /v1/grants",
            )
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
    parsed = parse_v1_grant_issue_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    return issue_v1_grant_response(
        parsed,
        identity=identity,
        service=service,
        now=now,
    )


def _parse_list_filters(query_string: str) -> ParsedGrantListFilters | V1HttpResponse:
    params = parse_qs(query_string, keep_blank_values=True)
    allowed = {"agent_id", "status"}
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
    return ParsedGrantListFilters(agent_id=values["agent_id"], status=values["status"])


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
