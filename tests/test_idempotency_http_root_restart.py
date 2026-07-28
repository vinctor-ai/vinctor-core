from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

import pytest
from idempotency_http_fixtures import (
    AGENT_HEADERS,
    post_json,
    running_server,
)
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
)


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

def test_pop_token_replays_exactly_after_sqlite_restart_without_plaintext(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    database = tmp_path / "pop-restart.sqlite3"
    raw_key = "restart-pop-key"
    body = {
        "grant_ref": "grt_seed",
        "audience": "pep_main",
        "ttl_seconds": 60,
        "pop": True,
    }
    caplog.set_level(logging.ERROR)
    service, connection = configured_sqlite_service(database)
    seed_success_routes(service)
    before = persisted_counts(connection)
    with running_server(service) as server:
        first = post_json(
            server,
            "/v1/tokens",
            body,
            {**AGENT_HEADERS, "Idempotency-Key": raw_key},
        )
    after_first = persisted_counts(connection)
    connection.close()

    restarted_service, restarted_connection = configured_sqlite_service(database)
    with running_server(restarted_service) as server:
        replay = post_json(
            server,
            "/v1/tokens",
            body,
            {**AGENT_HEADERS, "Idempotency-Key": raw_key},
        )
    after_replay = persisted_counts(restarted_connection)
    restarted_connection.close()

    payload = json.loads(first.body)
    assert isinstance(payload, dict)
    token = payload["token"]
    pop_secret = payload["pop_secret"]
    assert isinstance(token, str)
    assert isinstance(pop_secret, str)
    assert _wire(replay) == _wire(first)
    assert after_first.tokens == before.tokens + 1
    assert after_first.audits == before.audits + 1
    assert after_first.results == before.results + 1
    assert after_first.reservations == before.reservations + 1
    assert after_replay == after_first

    with closing(sqlite3.connect(database)) as scan_connection:
        sql_dump = "\n".join(scan_connection.iterdump())
        authoritative_rows = scan_connection.execute(
            "SELECT pop_secret FROM subject_tokens WHERE pop_secret = ?",
            (pop_secret,),
        ).fetchall()
        idempotency_rows = repr(
            (
                scan_connection.execute("SELECT * FROM idempotency_results").fetchall(),
                scan_connection.execute("SELECT * FROM idempotency_cipher_nonces").fetchall(),
                scan_connection.execute("SELECT * FROM idempotency_cipher_key_versions").fetchall(),
            )
        )
    database_bytes = b"".join(
        path.read_bytes()
        for path in (
            database,
            Path(f"{database}-wal"),
            Path(f"{database}-journal"),
        )
        if path.exists()
    )
    globally_forbidden = (raw_key, token, first.body.decode("utf-8"))
    pop_secret_dump_lines = tuple(line for line in sql_dump.splitlines() if pop_secret in line)
    assert authoritative_rows == [(pop_secret,)]
    assert len(pop_secret_dump_lines) == 1
    assert pop_secret_dump_lines[0].startswith('INSERT INTO "subject_tokens"')
    assert all(value not in sql_dump for value in globally_forbidden)
    assert all(value not in idempotency_rows for value in (*globally_forbidden, pop_secret))
    forbidden_text = (*globally_forbidden, pop_secret)
    assert all(value not in caplog.text for value in forbidden_text)
    assert raw_key.encode("ascii") not in database_bytes
    assert token.encode("ascii") not in database_bytes
    assert pop_secret.encode("ascii") in database_bytes
    assert first.body not in database_bytes
