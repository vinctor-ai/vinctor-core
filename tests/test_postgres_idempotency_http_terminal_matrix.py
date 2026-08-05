from __future__ import annotations

import base64
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from idempotency_http_fixtures import NOW
from idempotency_http_memory_transport import post_memory_raw_json
from idempotency_http_replay_scenarios import state_value
from idempotency_http_terminal_case import RouteCase
from idempotency_http_terminal_expectations import (
    EXPECTED_TERMINAL_RESPONSES,
    assert_expected_terminal_response,
)
from idempotency_http_terminal_matrix import ROUTE_CASES
from idempotency_sqlite_http_scenarios import (
    PersistedCounts,
    seed_success_routes,
)

from vinctor_core import BoundaryRegistrationInput
from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.postgres import PostgresV1Service, connect_postgres
from vinctor_service.postgres_connection import SerializedPostgresConnection


def _counts(connection: SerializedPostgresConnection) -> PersistedCounts:
    row = connection.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM grants), "
        "(SELECT COUNT(*) FROM subject_tokens), "
        "(SELECT COUNT(*) FROM boundaries), "
        "(SELECT COUNT(*) FROM auto_approval_rules), "
        "(SELECT COUNT(*) FROM grant_requests WHERE status <> 'pending'), "
        "(SELECT COUNT(*) FROM audit_events), "
        "(SELECT COUNT(*) FROM idempotency_results), "
        "(SELECT COUNT(*) FROM idempotency_cipher_nonces)"
    ).fetchone()
    connection.rollback()
    assert row is not None
    return PersistedCounts(*(int(value) for value in row))


def _prepare_terminal_case(
    service: PostgresV1Service,
    connection: SerializedPostgresConnection,
    case: RouteCase,
) -> None:
    if case.label == "boundary-semantic-400":
        service.register_boundary(
            BoundaryRegistrationInput(
                workspace_id="ws_main",
                name="matrix-boundary-invalid",
                runtime="existing-runtime",
                boundary_type="pretooluse",
            ),
            now=NOW,
            boundary_id="bnd_existing",
            enforcing_principal="workspace:ws_main",
        )
    if case.label == "auto-nested-400":
        connection.execute(
            "INSERT INTO agent_issuable_scope_bounds "
            "(workspace_id, agent_id, scopes_json, max_ttl_seconds, updated_at) "
            "VALUES (%s, %s, %s::jsonb, %s, %s)",
            (
                "ws_main",
                "agent_invalid_bounds",
                '["bad scope"]',
                3_600,
                NOW,
            ),
        )
        connection.commit()


@pytest.mark.parametrize("case", ROUTE_CASES, ids=lambda case: case.label)
def test_postgres_seven_route_terminal_matrix_is_cached_exactly_once(
    requires_postgres: str,
    case: RouteCase,
) -> None:
    encoded_key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{encoded_key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    connection = connect_postgres(requires_postgres)
    service = PostgresV1Service(connection, idempotency_keyring=keyring)
    try:
        epoch_row = connection.execute(
            "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
        ).fetchone()
        assert epoch_row is not None
        database_now = datetime.fromtimestamp(int(epoch_row[0]), UTC)
        connection.rollback()
        request_now = database_now if case.label == "token-success" else NOW
        seed_success_routes(service, now=request_now)
        _prepare_terminal_case(service, connection, case)
        before = _counts(connection)
        headers = {**case.headers, "Idempotency-Key": f"postgres-matrix-{case.label}"}
        body = b"" if case.payload is None else json.dumps(case.payload).encode("utf-8")
        raw_headers = tuple(headers.items())
        first = post_memory_raw_json(
            service,
            case.path,
            body,
            raw_headers,
            request_now=request_now,
        )
        after_first = _counts(connection)
        replay = post_memory_raw_json(
            service,
            case.path,
            body,
            raw_headers,
            request_now=request_now,
        )
        after_replay = _counts(connection)

        expected = EXPECTED_TERMINAL_RESPONSES[case.label]
        if case.label == "token-success":
            expected = replace(
                expected,
                exact_values=(
                    (("expires_at",), (request_now + timedelta(seconds=60)).isoformat()),
                ),
            )
        assert_expected_terminal_response(first, expected)
        assert replay == first
        assert after_first.results == before.results + 1
        assert after_first.reservations == before.reservations + 1
        assert state_value(after_first, case.state_field) == (
            state_value(before, case.state_field) + case.state_delta
        )
        assert after_first.audits == before.audits + case.audit_delta
        assert after_replay == after_first
    finally:
        service.close()
        connection.close()
