from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING

from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.grant_http_responses import (
    BAD_GRANT_REQUEST_REASONS,
    error_response,
    grant_body,
)
from vinctor_service.models import GrantIssueRequest
from vinctor_service.v1_http import V1HttpResponse

if TYPE_CHECKING:
    from vinctor_service.grant_http import GrantLifecycleService


@dataclass(frozen=True, slots=True)
class ParsedGrantIssueBody:
    agent_id: str
    scopes: tuple[str, ...]
    ttl_seconds: int


def issue_v1_grant_response(
    parsed: ParsedGrantIssueBody,
    *,
    identity: WorkspaceIdentity,
    service: GrantLifecycleService,
    now: datetime,
) -> V1HttpResponse:
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
        status_code = 400 if result.reason in BAD_GRANT_REQUEST_REASONS else 403
        return error_response(
            status_code,
            result.reason,
            result.reason,
            detail=result.detail,
        )
    if result.grant is None:
        return error_response(503, "service_unavailable", "grant issuance failed")

    return V1HttpResponse(
        status_code=201,
        body={**grant_body(result.grant), "audit_event_id": result.audit_event_id},
    )


def parse_v1_grant_issue_body(body: object) -> ParsedGrantIssueBody | V1HttpResponse:
    if not isinstance(body, dict):
        return error_response(400, "invalid_request", "request body must be a JSON object")

    required_fields = {"agent_id", "scopes", "ttl_seconds"}
    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields)
    if missing:
        return error_response(
            400,
            "invalid_request",
            f"missing required field: {missing[0]}",
        )
    if extra:
        return error_response(
            400,
            "invalid_request",
            f"unexpected field: {extra[0]}",
        )

    agent_id = body["agent_id"]
    if not isinstance(agent_id, str) or agent_id == "":
        return error_response(
            400,
            "invalid_request",
            "agent_id must be a non-empty string",
        )

    scopes = body["scopes"]
    if not isinstance(scopes, list) or not scopes:
        return error_response(
            400,
            "invalid_request",
            "scopes must be a non-empty array",
        )
    if any(not isinstance(scope, str) or scope == "" for scope in scopes):
        return error_response(
            400,
            "invalid_request",
            "scopes must contain only non-empty strings",
        )

    ttl_seconds = body["ttl_seconds"]
    if (
        not isinstance(ttl_seconds, int)
        or isinstance(ttl_seconds, bool)
        or ttl_seconds <= 0
    ):
        return error_response(
            400,
            "invalid_request",
            "ttl_seconds must be a positive integer",
        )

    return ParsedGrantIssueBody(
        agent_id=agent_id,
        scopes=tuple(scopes),
        ttl_seconds=ttl_seconds,
    )
