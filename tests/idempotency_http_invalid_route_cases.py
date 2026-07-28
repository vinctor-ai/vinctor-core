from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class InvalidRouteBody:
    label: str
    path: str
    body: bytes
    auth_header: tuple[str, str]
    expected_body: bytes


INVALID_ROUTE_BODIES = (
    InvalidRouteBody(
        "grant-field-type",
        "/v1/grants",
        b'{"agent_id":1,"scopes":["write:repo/feature/readme"],"ttl_seconds":60}',
        ("X-Workspace-Key", "workspace_key_main"),
        b'{"error": "invalid_request", "reason": "agent_id must be a non-empty string"}',
    ),
    InvalidRouteBody(
        "token-required-field",
        "/v1/tokens",
        b'{"grant_ref":"grt_seed"}',
        ("X-Agent-Key", "agent_key_main"),
        b'{"error": "invalid_request", "reason": "audience must be a non-empty string"}',
    ),
    InvalidRouteBody(
        "boundary-required-field",
        "/v1/boundaries",
        b'{"name":"bad","runtime":"codex","boundary_type":"pretooluse"}',
        ("X-Workspace-Key", "workspace_key_main"),
        b'{"error": "invalid_request", "reason": "missing required field: mode"}',
    ),
    InvalidRouteBody(
        "rule-field-type",
        "/v1/auto-approval-rules",
        b'{"name":"bad","target_agent_id":"agent_release","allowed_scopes":["write:repo/'
        b'feature/*"],"max_ttl_seconds":true}',
        ("X-Workspace-Key", "workspace_key_main"),
        b'{"error": "invalid_request", "reason": "max_ttl_seconds must be a positive integer"}',
    ),
    InvalidRouteBody(
        "approve-field-type",
        "/v1/grant-requests/grq_approve/approve",
        b'{"decision_reason":1}',
        ("X-Workspace-Key", "workspace_key_main"),
        b'{"error": "invalid_request", "reason": '
        b'"decision_reason must be a non-empty string when provided"}',
    ),
    InvalidRouteBody(
        "reject-extra-field",
        "/v1/grant-requests/grq_reject/reject",
        b'{"unexpected":"value"}',
        ("X-Workspace-Key", "workspace_key_main"),
        b'{"error": "invalid_request", "reason": "unexpected field: unexpected"}',
    ),
    InvalidRouteBody(
        "auto-nonempty-body",
        "/v1/grant-requests/grq_auto/auto-approve",
        b"{}",
        ("X-Workspace-Key", "workspace_key_main"),
        b'{"error": "invalid_request", "reason": "auto-approve request body must be empty"}',
    ),
)


def wire(response) -> tuple[int, str, int, bytes]:
    return (
        response.status_code,
        response.content_type,
        response.content_length,
        response.body,
    )
