from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from idempotency_http_fixtures import WORKSPACE_HEADERS
from idempotency_http_memory_transport import post_memory_raw_json
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    seed_success_routes,
)

from vinctor_service.idempotency_crypto import build_request_fingerprint
from vinctor_service.idempotency_http import (
    HttpIdempotencyRequest,
    execute_idempotent_http,
)
from vinctor_service.idempotency_models import RequestFingerprintInput

_KNOWN_GRANT_FINGERPRINT_HEX = "616c0b02309428fc742ae0af1105d10e641e8c4fbe92755e30e62331be22854d"


def test_live_handler_persists_canonical_fingerprint_known_vector(
    tmp_path: Path,
    record_property: Callable[[str, object], None],
) -> None:
    service, connection = configured_sqlite_service(tmp_path / "fingerprint.sqlite3")
    seed_success_routes(service)
    request_body = (
        b'{"agent_id":"agent_release","scopes":["write:repo/feature/readme"],"ttl_seconds":60}'
    )
    try:
        response = post_memory_raw_json(
            service,
            "/v1/grants",
            request_body,
            (*tuple(WORKSPACE_HEADERS.items()), ("Idempotency-Key", "known-vector")),
        )
        row = connection.execute(
            "SELECT request_fingerprint FROM idempotency_results WHERE operation = 'grant.issue.v1'"
        ).fetchone()
    finally:
        connection.close()

    assert response.status_code == 201
    assert row is not None
    persisted = bytes(row[0])
    expected = bytes(
        build_request_fingerprint(
            RequestFingerprintInput(
                method="POST",
                path="/v1/grants",
                authenticated_workspace_id="ws_main",
                authenticated_principal="workspace:ws_main",
                operation="grant.issue.v1",
                request_body=request_body,
            )
        )
    )
    assert expected.hex() == _KNOWN_GRANT_FINGERPRINT_HEX
    assert persisted == expected
    record_property("persisted_fingerprint_hex", persisted.hex())
    record_property("expected_fingerprint_hex", _KNOWN_GRANT_FINGERPRINT_HEX)
    record_property("first_status_code", response.status_code)


def test_semantic_encoding_precedes_invalid_key_and_store_access(
    record_property: Callable[[str, object], None],
) -> None:
    request = HttpIdempotencyRequest(
        fingerprint_input=RequestFingerprintInput(
            method="POST",
            path="/v1/grants",
            authenticated_workspace_id="ws_main",
            authenticated_principal="workspace:ws_main",
            operation="grant.issue.v1",
            request_body=b"\xff",
        ),
        raw_key_headers=("bad key",),
    )

    response = execute_idempotent_http(
        None,
        request,
        lambda: pytest.fail("mutation called"),
    )
    assert response.status_code == 503
    assert b"idempotency_unavailable" in response.body
    assert b"invalid_idempotency_key" not in response.body
    record_property("semantic_encoding_preceded_key_validation", True)
    record_property("service_was_unavailable", True)
