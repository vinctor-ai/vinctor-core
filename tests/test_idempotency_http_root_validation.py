from __future__ import annotations

from pathlib import Path

import pytest
from idempotency_http_fixtures import post_raw_json, running_server
from idempotency_http_invalid_route_cases import INVALID_ROUTE_BODIES, InvalidRouteBody, wire
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    persisted_counts,
    seed_success_routes,
)


@pytest.mark.parametrize("case", INVALID_ROUTE_BODIES, ids=lambda case: case.label)
def test_keyed_endpoint_schema_errors_are_uncached_before_key_work(
    case: InvalidRouteBody,
    tmp_path: Path,
) -> None:
    service, connection = configured_sqlite_service(tmp_path / f"{case.label}.sqlite3")
    seed_success_routes(service)
    try:
        before = persisted_counts(connection)
        with running_server(service) as server:
            response = post_raw_json(
                server,
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
def test_endpoint_schema_error_precedes_invalid_key(
    case: InvalidRouteBody,
    tmp_path: Path,
) -> None:
    service, connection = configured_sqlite_service(tmp_path / f"precedence-{case.label}.sqlite3")
    seed_success_routes(service)
    try:
        before = persisted_counts(connection)
        with running_server(service) as server:
            response = post_raw_json(
                server,
                case.path,
                case.body,
                (case.auth_header, ("Idempotency-Key", "bad key")),
            )
        assert response.body == case.expected_body
        assert persisted_counts(connection) == before
    finally:
        connection.close()
