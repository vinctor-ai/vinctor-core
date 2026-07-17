from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path

from tools.mock_vinctor_service import (
    MOCK_AGENT_KEY,
    MOCK_GRANT_REF,
    MockDecisionConfig,
    create_mock_server,
    load_mock_config,
    merge_cli_config,
    run_server_in_thread,
)


def body(*, action: str = "execute", resource: str = "ci/test") -> dict[str, str]:
    return {"grant_ref": MOCK_GRANT_REF, "action": action, "resource": resource}


@contextmanager
def running_mock(config: MockDecisionConfig) -> Iterator:
    server = create_mock_server(("127.0.0.1", 0), config=config)
    thread = run_server_in_thread(server)
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def post_json(
    server,
    *,
    payload: object,
    headers: dict[str, str] | None = None,
    include_agent_key: bool = True,
) -> tuple[int, dict[str, object]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    request_headers = dict(headers or {})
    if include_agent_key:
        request_headers = {"X-Agent-Key": MOCK_AGENT_KEY, **request_headers}
    conn.request(
        "POST",
        "/v1/enforce",
        body=json.dumps(payload),
        headers=request_headers,
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


def raw_post(
    server,
    *,
    raw_body: str,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, object]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    conn.request(
        "POST",
        "/v1/enforce",
        body=raw_body,
        headers={"X-Agent-Key": MOCK_AGENT_KEY, **(headers or {})},
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


def test_mock_service_returns_valid_permit_response() -> None:
    config = MockDecisionConfig(default_decision="deny", permit=frozenset({"execute:ci/test"}))

    with running_mock(config) as server:
        status, response = post_json(server, payload=body())

    assert status == 200
    assert response == {"decision": "permit", "audit_event_id": "evt_mock_1"}


def test_mock_service_explicit_deny_wins_over_permit() -> None:
    config = MockDecisionConfig(
        default_decision="permit",
        permit=frozenset({"deploy:npm/package"}),
        deny=frozenset({"deploy:npm/package"}),
    )

    with running_mock(config) as server:
        status, response = post_json(
            server,
            payload=body(action="deploy", resource="npm/package"),
        )

    assert status == 403
    assert response == {
        "decision": "deny",
        "error": "action_denied",
        "reason": "action_denied",
    }


def test_mock_service_default_deny_response() -> None:
    config = MockDecisionConfig(default_decision="deny")

    with running_mock(config) as server:
        status, response = post_json(
            server,
            payload=body(action="read", resource="secret/env"),
        )

    assert status == 403
    assert response["decision"] == "deny"
    assert response["reason"] == "action_denied"


def test_mock_service_rejects_extra_body_fields() -> None:
    with running_mock(MockDecisionConfig()) as server:
        status, response = post_json(server, payload={**body(), "boundary_id": "bnd_mock"})

    assert status == 400
    assert response == {
        "error": "invalid_request",
        "reason": "unexpected field: boundary_id",
    }


def test_mock_service_rejects_missing_body_fields() -> None:
    with running_mock(MockDecisionConfig()) as server:
        status, response = post_json(server, payload={"grant_ref": MOCK_GRANT_REF})

    assert status == 400
    assert response == {
        "error": "invalid_request",
        "reason": "missing required field: action",
    }


def test_mock_service_rejects_non_string_body_values() -> None:
    with running_mock(MockDecisionConfig()) as server:
        status, response = post_json(
            server,
            payload={"grant_ref": MOCK_GRANT_REF, "action": "execute", "resource": 123},
        )

    assert status == 400
    assert response == {
        "error": "invalid_request",
        "reason": "resource must be a non-empty string",
    }


def test_mock_service_requires_agent_key() -> None:
    with running_mock(MockDecisionConfig()) as server:
        status, response = post_json(server, payload=body(), include_agent_key=False)

    assert status == 401
    assert response == {
        "error": "authentication_required",
        "reason": "valid X-Agent-Key header is required",
    }


def test_mock_service_accepts_optional_boundary_header() -> None:
    with running_mock(MockDecisionConfig()) as server:
        status, response = post_json(
            server,
            payload=body(),
            headers={"X-Vinctor-Boundary-Id": "bnd_mock"},
        )
        log = tuple(server.mock_log)

    assert status == 200
    assert response == {"decision": "permit", "audit_event_id": "evt_mock_1"}
    assert log[0].boundary_id == "bnd_mock"
    assert log[0].action_resource == "execute:ci/test"


def test_mock_service_fail_all_unavailable_mode() -> None:
    config = MockDecisionConfig(mode="unavailable", status=503)

    with running_mock(config) as server:
        status, response = post_json(server, payload=body())

    assert status == 503
    assert response == {
        "error": "service_unavailable",
        "reason": "mock service unavailable",
    }


def test_mock_service_rejects_invalid_json() -> None:
    with running_mock(MockDecisionConfig()) as server:
        status, response = raw_post(server, raw_body="{not-json")

    assert status == 400
    assert response == {
        "error": "invalid_json",
        "reason": "request body must be valid JSON",
    }


def test_mock_service_parses_startup_config(tmp_path: Path) -> None:
    config_path = tmp_path / "mock-vinctor.json"
    config_path.write_text(
        json.dumps(
            {
                "default_decision": "deny",
                "permit": ["execute:ci/test"],
                "deny": ["deploy:npm/package"],
            }
        ),
        encoding="utf-8",
    )

    config = load_mock_config(config_path)
    merged = merge_cli_config(config, permit=["read:secret/env"], status=503)

    assert config.default_decision == "deny"
    assert config.permit == frozenset({"execute:ci/test"})
    assert config.deny == frozenset({"deploy:npm/package"})
    assert merged.mode == "unavailable"
    assert merged.permit == frozenset({"execute:ci/test", "read:secret/env"})
