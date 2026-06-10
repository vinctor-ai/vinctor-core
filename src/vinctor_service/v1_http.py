from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from vinctor_service.models import V1EnforceRequest, V1EnforceResponse


@dataclass(frozen=True)
class AgentIdentity:
    workspace_id: str
    agent_id: str


@dataclass(frozen=True)
class V1HttpResponse:
    status_code: int
    body: dict[str, Any]


class V1EnforceService(Protocol):
    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse: ...


def handle_v1_enforce_http(
    *,
    headers: Mapping[str, str],
    body: object,
    agent_identities: Mapping[str, AgentIdentity],
    service: V1EnforceService,
    now: datetime,
) -> V1HttpResponse:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    agent_key = normalized_headers.get("x-agent-key")
    if agent_key is None or agent_key not in agent_identities:
        return _error(401, "authentication_required", "valid X-Agent-Key header is required")

    parsed = _parse_enforce_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    identity = agent_identities[agent_key]
    request = V1EnforceRequest(
        workspace_id=identity.workspace_id,
        agent_id=identity.agent_id,
        grant_ref=parsed["grant_ref"],
        action=parsed["action"],
        resource=parsed["resource"],
        boundary_id=normalized_headers.get("x-vinctor-boundary-id"),
    )
    return _http_response_from_enforce(service.enforce(request, now=now))


def _parse_enforce_body(body: object) -> dict[str, str] | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")

    required_fields = {"grant_ref", "action", "resource"}
    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields)
    if missing:
        return _error(400, "invalid_request", f"missing required field: {missing[0]}")
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")

    parsed: dict[str, str] = {}
    for field in sorted(required_fields):
        value = body[field]
        if not isinstance(value, str) or value == "":
            return _error(400, "invalid_request", f"{field} must be a non-empty string")
        parsed[field] = value
    return parsed


def _http_response_from_enforce(response: V1EnforceResponse) -> V1HttpResponse:
    if response.decision == "permit":
        return V1HttpResponse(
            status_code=response.status_code,
            body={
                "decision": "permit",
                "grant_id": response.grant_id,
                "agent_id": response.agent_id,
                "scope_matched": response.scope_matched,
                "audit_event_id": response.audit_event_id,
            },
        )

    if response.decision == "deny":
        return V1HttpResponse(
            status_code=response.status_code,
            body={
                "decision": "deny",
                "error": response.error,
                "reason": response.reason,
                "grant_id": response.grant_id,
                "agent_id": response.agent_id,
                "audit_event_id": response.audit_event_id,
            },
        )

    return _error(
        response.status_code,
        response.error or "service_unavailable",
        response.reason or "no decision was recorded",
    )


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})
