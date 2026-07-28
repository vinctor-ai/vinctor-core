from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest
from idempotency_http_fixtures import AGENT_HEADERS, WORKSPACE_HEADERS
from idempotency_http_invalid_route_cases import INVALID_ROUTE_BODIES, wire
from idempotency_http_memory_transport import post_memory_raw_json
from idempotency_http_terminal_matrix import ROUTE_CASES
from idempotency_legacy_routes import _deterministic_ids
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
)

from vinctor_service import InMemoryV1Service
from vinctor_service.v1_http import DEFAULT_SUBJECT_TOKEN_TTL_SECONDS


@pytest.mark.parametrize("case", INVALID_ROUTE_BODIES, ids=lambda case: case.label)
def test_memory_keyed_endpoint_schema_errors_are_uncached(
    case,
    tmp_path: Path,
) -> None:
    service, connection = configured_sqlite_service(tmp_path / f"{case.label}.sqlite3")
    seed_success_routes(service)
    try:
        before = persisted_counts(connection)
        response = post_memory_raw_json(
            service,
            case.path,
            case.body,
            (case.auth_header, ("Idempotency-Key", f"valid-{case.label}")),
        )
        assert wire(response) == (
            400,
            "application/json",
            len(case.expected_body),
            case.expected_body,
        )
        assert persisted_counts(connection) == before
    finally:
        connection.close()


@pytest.mark.parametrize("case", INVALID_ROUTE_BODIES, ids=lambda case: case.label)
def test_memory_endpoint_schema_error_precedes_invalid_key(
    case,
    tmp_path: Path,
) -> None:
    service, connection = configured_sqlite_service(tmp_path / f"precedence-{case.label}.sqlite3")
    seed_success_routes(service)
    try:
        before = persisted_counts(connection)
        response = post_memory_raw_json(
            service,
            case.path,
            case.body,
            (case.auth_header, ("Idempotency-Key", "bad key")),
        )
        assert response.body == case.expected_body
        assert persisted_counts(connection) == before
    finally:
        connection.close()


def test_memory_token_effective_defaults_replay(tmp_path: Path) -> None:
    service, connection = configured_sqlite_service(tmp_path / "token-defaults.sqlite3")
    seed_success_routes(service)
    headers = (("X-Agent-Key", "agent_key_main"), ("Idempotency-Key", "token-defaults"))
    try:
        first = post_memory_raw_json(
            service,
            "/v1/tokens",
            b'{"grant_ref":"grt_seed","audience":"pep_main"}',
            headers,
        )
        after_first = persisted_counts(connection)
        replay = post_memory_raw_json(
            service,
            "/v1/tokens",
            (
                b'{"pop":false,"resource":null,"ttl_seconds":'
                + str(DEFAULT_SUBJECT_TOKEN_TTL_SECONDS).encode("ascii")
                + b',"audience":"pep_main","action":null,"grant_ref":"grt_seed"}'
            ),
            headers,
        )
        assert wire(replay) == wire(first)
        assert persisted_counts(connection) == after_first
    finally:
        connection.close()


def test_memory_all_seven_operation_names_are_versioned(tmp_path: Path) -> None:
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
        for case in ROUTE_CASES:
            if case.label in success_labels:
                body = b"" if case.payload is None else json.dumps(case.payload).encode("utf-8")
                response = post_memory_raw_json(
                    service,
                    case.path,
                    body,
                    (
                        *tuple(case.headers.items()),
                        ("Idempotency-Key", f"operation-{case.label}"),
                    ),
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


def test_memory_unkeyed_custom_runtime_keeps_legacy_wire(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _deterministic_ids(monkeypatch)
    service = InMemoryV1Service()
    response = post_memory_raw_json(
        service,
        "/v1/boundaries",
        (
            b'{"name":"pin-boundary-custom","runtime":"custom-runtime",'
            b'"boundary_type":"pretooluse","mode":"fail_closed"}'
        ),
        tuple(WORKSPACE_HEADERS.items()),
    )
    expected = (
        b'{"boundary_id": "bnd_pin_legacy", "boundary_type": "pretooluse", '
        b'"mode": "fail_closed", "name": "pin-boundary-custom", '
        b'"runtime": "custom-runtime", "status": "active"}'
    )
    assert wire(response) == (201, "application/json", len(expected), expected)
    assert len(service.boundary_registry.list_for_workspace("ws_main")) == 1


def test_memory_pop_token_restart_replay_and_plaintext_scan(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    database = tmp_path / "pop-restart.sqlite3"
    raw_key = "restart-pop-key"
    request_body = b'{"grant_ref":"grt_seed","audience":"pep_main","ttl_seconds":60,"pop":true}'
    headers = (*tuple(AGENT_HEADERS.items()), ("Idempotency-Key", raw_key))
    caplog.set_level(logging.ERROR)
    service, connection = configured_sqlite_service(database)
    seed_success_routes(service)
    before = persisted_counts(connection)
    first = post_memory_raw_json(service, "/v1/tokens", request_body, headers)
    after_first = persisted_counts(connection)
    connection.close()

    restarted_service, restarted_connection = configured_sqlite_service(database)
    replay = post_memory_raw_json(restarted_service, "/v1/tokens", request_body, headers)
    after_replay = persisted_counts(restarted_connection)
    restarted_connection.close()

    payload = json.loads(first.body)
    assert isinstance(payload, dict)
    token = payload["token"]
    pop_secret = payload["pop_secret"]
    assert isinstance(token, str)
    assert isinstance(pop_secret, str)
    assert wire(replay) == wire(first)
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
    stored_bytes = b"".join(
        path.read_bytes()
        for path in (database, Path(f"{database}-wal"), Path(f"{database}-journal"))
        if path.exists()
    )
    forbidden = {
        "raw_idempotency_key": raw_key,
        "bearer_token": token,
        "pop_secret": pop_secret,
        "serialized_response": first.body.decode("utf-8"),
    }
    pop_secret_dump_lines = tuple(line for line in sql_dump.splitlines() if pop_secret in line)
    log_hits = tuple(label for label, value in forbidden.items() if value in caplog.text)
    byte_hits = tuple(
        label for label, value in forbidden.items() if value.encode("utf-8") in stored_bytes
    )
    assert authoritative_rows == [(pop_secret,)]
    assert len(pop_secret_dump_lines) == 1
    assert pop_secret_dump_lines[0].startswith('INSERT INTO "subject_tokens"')
    assert all(value not in idempotency_rows for value in forbidden.values())
    assert log_hits == ()
    assert byte_hits == ("pop_secret",)
