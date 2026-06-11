from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from vinctor_mcp_server.service_client import (
    VinctorServiceClient,
    VinctorServiceClientError,
)


class FakeResponse:
    def __init__(self, status: int, body: dict[str, Any]) -> None:
        self.status = status
        self._body = body

    def read(self) -> bytes:
        return json.dumps(self._body).encode("utf-8")


class FakeConnection:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.requests: list[dict[str, Any]] = []
        self.closed = False

    def request(
        self,
        method: str,
        path: str,
        body: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.requests.append(
            {
                "method": method,
                "path": path,
                "body": body,
                "headers": headers or {},
            }
        )

    def getresponse(self) -> FakeResponse:
        return self.responses.pop(0)

    def close(self) -> None:
        self.closed = True


def make_client(
    response: FakeResponse,
) -> tuple[VinctorServiceClient, FakeConnection]:
    conn = FakeConnection([response])
    client = VinctorServiceClient(
        endpoint="http://127.0.0.1:8765",
        workspace_key="wsk_demo",
        connection_factory=lambda host, port, timeout: conn,
    )
    return client, conn


def test_client_reads_health_without_workspace_key() -> None:
    client, conn = make_client(
        FakeResponse(200, {"status": "ok", "service": "vinctor-service", "mode": "local"})
    )

    body = client.status()

    assert body["status"] == "ok"
    assert conn.requests == [
        {
            "method": "GET",
            "path": "/healthz",
            "body": None,
            "headers": {},
        }
    ]
    assert conn.closed is True


def test_client_gets_boundary_with_workspace_key() -> None:
    client, conn = make_client(
        FakeResponse(
            200,
            {
                "boundary_id": "bnd_main",
                "name": "codex-local",
                "runtime": "codex",
                "boundary_type": "pretooluse",
                "mode": "fail_closed",
                "status": "active",
            },
        )
    )

    body = client.get_boundary("bnd_main")

    assert body["boundary_id"] == "bnd_main"
    assert conn.requests[0] == {
        "method": "GET",
        "path": "/v1/boundaries/bnd_main",
        "body": None,
        "headers": {"X-Workspace-Key": "wsk_demo"},
    }


def test_client_lists_audit_events_with_read_only_filters() -> None:
    client, conn = make_client(FakeResponse(200, {"audit_events": []}))

    body = client.list_audit_events(
        limit=5,
        event_type="action_denied",
        request_id="grq_demo",
    )

    assert body == {"audit_events": []}
    request = conn.requests[0]
    assert request["method"] == "GET"
    assert request["headers"] == {"X-Workspace-Key": "wsk_demo"}
    parsed = urlsplit(request["path"])
    assert parsed.path == "/v1/audit-events"
    assert parse_qs(parsed.query) == {
        "event_type": ["action_denied"],
        "limit": ["5"],
        "request_id": ["grq_demo"],
    }


def test_client_raises_for_service_errors_without_exposing_credentials() -> None:
    client, _ = make_client(
        FakeResponse(
            401,
            {
                "error": "authentication_required",
                "reason": "valid X-Workspace-Key header is required",
            },
        )
    )

    with pytest.raises(VinctorServiceClientError) as error:
        client.get_grant("grt_demo")

    assert "authentication_required" in str(error.value)
    assert "wsk_demo" not in str(error.value)


def test_client_has_no_enforce_method() -> None:
    client, _ = make_client(FakeResponse(200, {}))

    assert not hasattr(client, "enforce")
