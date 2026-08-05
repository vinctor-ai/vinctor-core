from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass

from idempotency_http_fixtures import RawResponse

JsonPath = tuple[str, ...]
PathValue = tuple[JsonPath, object]
PathPrefix = tuple[JsonPath, str]
PathKeys = tuple[JsonPath, frozenset[str]]


@dataclass(frozen=True, slots=True)
class ExpectedTerminalResponse:
    status_code: int
    exact_body: Mapping[str, object] | None = None
    exact_values: tuple[PathValue, ...] = ()
    prefixed_values: tuple[PathPrefix, ...] = ()
    object_keys: tuple[PathKeys, ...] = ()


def assert_expected_terminal_response(
    response: RawResponse,
    expected: ExpectedTerminalResponse,
) -> None:
    assert response.status_code == expected.status_code
    assert response.content_type == "application/json"
    assert response.content_length == len(response.body)
    decoded = json.loads(response.body)
    assert isinstance(decoded, dict)
    if expected.exact_body is not None:
        expected_body = json.dumps(expected.exact_body, sort_keys=True).encode("utf-8")
        assert response.body == expected_body
        assert response.content_length == len(expected_body)
        return
    assert response.body == json.dumps(decoded, sort_keys=True).encode("utf-8")
    for path, keys in expected.object_keys:
        value = _path_value(decoded, path)
        assert isinstance(value, dict)
        assert frozenset(value) == keys
    for path, value in expected.exact_values:
        assert _path_value(decoded, path) == value
    for path, prefix in expected.prefixed_values:
        value = _path_value(decoded, path)
        assert isinstance(value, str)
        assert value.startswith(prefix)


def _path_value(body: Mapping[str, object], path: JsonPath) -> object:
    current: object = body
    for key in path:
        assert isinstance(current, dict)
        current = current[key]
    return current


def _error(status_code: int, error: str, reason: str, *, detail: str | None = None):
    body: dict[str, object] = {"error": error, "reason": reason}
    if detail is not None:
        body["detail"] = detail
    return ExpectedTerminalResponse(status_code=status_code, exact_body=body)


_GRANT_KEYS = frozenset(
    {
        "agent_id",
        "audit_event_id",
        "expires_at",
        "grant_id",
        "grant_ref",
        "scopes",
        "status",
        "workspace_id",
    }
)
_NESTED_GRANT_KEYS = _GRANT_KEYS - {"audit_event_id"}
_REQUEST_KEYS = frozenset(
    {
        "boundary_id",
        "created_at",
        "decided_at",
        "decided_by",
        "decision_reason",
        "issued_grant_ref",
        "reason",
        "repo",
        "request_id",
        "requested_scopes",
        "requested_ttl_seconds",
        "requester_agent_id",
        "requester_runtime",
        "session_id",
        "status",
        "target_agent_id",
        "task_id",
        "workspace_id",
        "worktree",
    }
)
_REQUEST_STATIC = (
    (("created_at",), "2026-07-19T12:00:00+00:00"),
    (("reason",), "idempotency HTTP matrix"),
    (("requested_scopes",), ["write:repo/feature/readme"]),
    (("requested_ttl_seconds",), 3_600),
    (("requester_agent_id",), "agent_release"),
    (("workspace_id",), "ws_main"),
)
