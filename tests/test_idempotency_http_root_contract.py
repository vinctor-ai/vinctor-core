from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest
from idempotency_http_fixtures import (
    WORKSPACE_HEADERS,
    post_json,
    post_raw_json,
    running_server,
)
from idempotency_http_terminal_matrix import ROUTE_CASES
from idempotency_legacy_routes import _deterministic_ids
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
)

from vinctor_service import InMemoryV1Service
from vinctor_service.v1_http import DEFAULT_SUBJECT_TOKEN_TTL_SECONDS


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


def _wire(response) -> tuple[int, str, int, bytes]:
    return (
        response.status_code,
        response.content_type,
        response.content_length,
        response.body,
    )

def test_token_omitted_and_explicit_effective_defaults_replay(tmp_path: Path) -> None:
    service, connection = configured_sqlite_service(tmp_path / "token-defaults.sqlite3")
    seed_success_routes(service)
    try:
        with running_server(service) as server:
            first = post_raw_json(
                server,
                "/v1/tokens",
                b'{"grant_ref":"grt_seed","audience":"pep_main"}',
                (("X-Agent-Key", "agent_key_main"), ("Idempotency-Key", "token-defaults")),
            )
            after_first = persisted_counts(connection)
            replay = post_raw_json(
                server,
                "/v1/tokens",
                (
                    b'{"pop":false,"resource":null,"ttl_seconds":'
                    + str(DEFAULT_SUBJECT_TOKEN_TTL_SECONDS).encode("ascii")
                    + b',"audience":"pep_main","action":null,"grant_ref":"grt_seed"}'
                ),
                (("X-Agent-Key", "agent_key_main"), ("Idempotency-Key", "token-defaults")),
            )
        assert _wire(replay) == _wire(first)
        assert persisted_counts(connection) == after_first
    finally:
        connection.close()

def test_all_seven_persisted_operation_names_are_versioned(tmp_path: Path) -> None:
    service, connection = configured_sqlite_service(tmp_path / "operations.sqlite3")
    seed_success_routes(service)
    success_labels = {
        "grant-success",
        "token-success",
        "boundary-success",
        "rule-success",
        "approve-success",
        "reject-success",
        "auto-success",
    }
    try:
        with running_server(service) as server:
            for case in ROUTE_CASES:
                if case.label in success_labels:
                    response = post_json(
                        server,
                        case.path,
                        case.payload,
                        {**case.headers, "Idempotency-Key": f"operation-{case.label}"},
                    )
                    assert response.status_code == case.status_code
        rows = connection.execute(
            "SELECT operation FROM idempotency_results ORDER BY operation"
        ).fetchall()
        assert {str(row[0]) for row in rows} == {
            "auto_approval_rule.create.v1",
            "boundary.create.v1",
            "grant.issue.v1",
            "grant_request.approve.v1",
            "grant_request.auto_approve.v1",
            "grant_request.reject.v1",
            "subject_token.mint.v1",
        }
    finally:
        connection.close()

def test_unkeyed_custom_boundary_runtime_keeps_legacy_wire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _deterministic_ids(monkeypatch)
    service = InMemoryV1Service()
    with running_server(service) as server:
        response = post_json(
            server,
            "/v1/boundaries",
            {
                "name": "pin-boundary-custom",
                "runtime": "custom-runtime",
                "boundary_type": "pretooluse",
                "mode": "fail_closed",
            },
            WORKSPACE_HEADERS,
        )
    expected = (
        b'{"boundary_id": "bnd_pin_legacy", "boundary_type": "pretooluse", '
        b'"mode": "fail_closed", "name": "pin-boundary-custom", '
        b'"runtime": "custom-runtime", "status": "active"}'
    )
    assert _wire(response) == (201, "application/json", len(expected), expected)
    assert len(service.boundary_registry.list_for_workspace("ws_main")) == 1
