from __future__ import annotations

import json
import socket
import time
from collections.abc import Iterator
from contextlib import closing, contextmanager
from threading import Thread
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
    *,
    service_operator_key: str | None = None,
) -> tuple[VinctorServiceClient, FakeConnection]:
    conn = FakeConnection([response])
    client = VinctorServiceClient(
        endpoint="http://127.0.0.1:8765",
        workspace_key="wsk_demo",
        service_operator_key=service_operator_key,
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
        event_class="control",
        event_type="action_denied",
        request_id="grq_demo",
        agent_id="agent_release",
        reason_code="agent_key_invalid",
        enforcing_principal="pep_git_host",
        subject_token_verified=False,
    )

    assert body == {"audit_events": []}
    request = conn.requests[0]
    assert request["method"] == "GET"
    assert request["headers"] == {"X-Workspace-Key": "wsk_demo"}
    parsed = urlsplit(request["path"])
    assert parsed.path == "/v1/audit-events"
    assert parse_qs(parsed.query) == {
        "agent_id": ["agent_release"],
        "event_class": ["control"],
        "event_type": ["action_denied"],
        "enforcing_principal": ["pep_git_host"],
        "subject_token_verified": ["false"],
        "limit": ["5"],
        "reason_code": ["agent_key_invalid"],
        "request_id": ["grq_demo"],
    }


def test_client_rejects_invalid_audit_event_class_before_request() -> None:
    client, conn = make_client(FakeResponse(200, {"audit_events": []}))

    with pytest.raises(
        ValueError, match="event_class must be one of: control, decision"
    ):
        client.list_audit_events(event_class="security")

    assert conn.requests == []


def test_client_reads_service_auth_failures_with_dedicated_key() -> None:
    client, conn = make_client(
        FakeResponse(200, {"auth_failures": []}),
        service_operator_key="sok_demo",
    )

    body = client.list_service_auth_failures(limit=17)

    assert body == {"auth_failures": []}
    assert conn.requests[0] == {
        "method": "GET",
        "path": "/v1/service/audit/auth-failures?limit=17",
        "body": None,
        "headers": {"X-Service-Operator-Key": "sok_demo"},
    }


def test_client_does_not_substitute_workspace_key_for_service_operator_key() -> None:
    client, conn = make_client(FakeResponse(401, {"error": "authentication_required"}))

    with pytest.raises(VinctorServiceClientError):
        client.list_service_auth_failures()

    assert conn.requests[0]["headers"] == {}


def test_client_reads_grant_requests_with_workspace_key() -> None:
    client, conn = make_client(FakeResponse(200, {"grant_requests": []}))

    body = client.list_grant_requests()

    assert body == {"grant_requests": []}
    assert conn.requests[0] == {
        "method": "GET",
        "path": "/v1/grant-requests",
        "body": None,
        "headers": {"X-Workspace-Key": "wsk_demo"},
    }


def test_client_auto_approves_grant_request_without_body() -> None:
    client, conn = make_client(
        FakeResponse(200, {"request_id": "grq_x", "status": "approved"})
    )

    body = client.auto_approve_grant_request("grq_x")

    assert body == {"request_id": "grq_x", "status": "approved"}
    assert conn.requests[0] == {
        "method": "POST",
        "path": "/v1/grant-requests/grq_x/auto-approve",
        "body": None,
        "headers": {"X-Workspace-Key": "wsk_demo"},
    }


def test_client_lists_grants_with_read_only_filters() -> None:
    client, conn = make_client(FakeResponse(200, {"grants": []}))

    body = client.list_grants(agent_id="agent_release", status="active")

    assert body == {"grants": []}
    request = conn.requests[0]
    assert request["method"] == "GET"
    assert request["headers"] == {"X-Workspace-Key": "wsk_demo"}
    parsed = urlsplit(request["path"])
    assert parsed.path == "/v1/grants"
    assert parse_qs(parsed.query) == {
        "agent_id": ["agent_release"],
        "status": ["active"],
    }


def test_client_gets_grant_request_with_encoded_path() -> None:
    client, conn = make_client(FakeResponse(200, {"request_id": "grq_demo"}))

    body = client.get_grant_request("../../../healthz")

    assert body == {"request_id": "grq_demo"}
    assert conn.requests[0] == {
        "method": "GET",
        "path": "/v1/grant-requests/..%2F..%2F..%2Fhealthz",
        "body": None,
        "headers": {"X-Workspace-Key": "wsk_demo"},
    }


def test_client_reads_auto_approval_rules_with_workspace_key() -> None:
    client, conn = make_client(FakeResponse(200, {"auto_approval_rules": []}))

    body = client.list_auto_approval_rules()

    assert body == {"auto_approval_rules": []}
    assert conn.requests[0] == {
        "method": "GET",
        "path": "/v1/auto-approval-rules",
        "body": None,
        "headers": {"X-Workspace-Key": "wsk_demo"},
    }


def test_client_creates_and_toggles_boundaries() -> None:
    conn = FakeConnection(
        [
            FakeResponse(201, {"boundary_id": "bnd_x", "status": "active"}),
            FakeResponse(200, {"boundary_id": "bnd_x", "status": "disabled"}),
            FakeResponse(200, {"boundary_id": "bnd_x", "status": "active"}),
        ]
    )
    client = VinctorServiceClient(
        endpoint="http://127.0.0.1:8765",
        workspace_key="wsk_demo",
        connection_factory=lambda host, port, timeout: conn,
    )

    client.create_boundary(
        name="codex-local",
        runtime="codex",
        boundary_type="pretooluse",
        mode="fail_closed",
    )
    client.disable_boundary("bnd_x")
    client.enable_boundary("bnd_x")

    assert [request["path"] for request in conn.requests] == [
        "/v1/boundaries",
        "/v1/boundaries/bnd_x/disable",
        "/v1/boundaries/bnd_x/enable",
    ]
    assert json.loads(conn.requests[0]["body"]) == {
        "name": "codex-local",
        "runtime": "codex",
        "boundary_type": "pretooluse",
        "mode": "fail_closed",
    }
    assert conn.requests[1]["body"] is None
    assert conn.requests[2]["body"] is None


def test_client_creates_and_disables_auto_approval_rules() -> None:
    conn = FakeConnection(
        [
            FakeResponse(201, {"rule_id": "apr_x", "status": "active"}),
            FakeResponse(200, {"rule_id": "apr_x", "status": "disabled"}),
        ]
    )
    client = VinctorServiceClient(
        endpoint="http://127.0.0.1:8765",
        workspace_key="wsk_demo",
        connection_factory=lambda host, port, timeout: conn,
    )

    client.create_auto_approval_rule(
        name="CI",
        target_agent_id="agent_ci",
        allowed_scopes=["execute:ci/*"],
        max_ttl_seconds=900,
    )
    client.disable_auto_approval_rule("apr_x")

    assert [request["path"] for request in conn.requests] == [
        "/v1/auto-approval-rules",
        "/v1/auto-approval-rules/apr_x/disable",
    ]
    assert json.loads(conn.requests[0]["body"]) == {
        "name": "CI",
        "target_agent_id": "agent_ci",
        "allowed_scopes": ["execute:ci/*"],
        "max_ttl_seconds": 900,
    }
    assert conn.requests[1]["body"] is None


def test_client_approves_grant_request_with_decision_reason() -> None:
    client, conn = make_client(
        FakeResponse(200, {"request_id": "grq_x", "status": "approved"})
    )

    body = client.approve_grant_request("grq_x", reason="looks safe")

    assert body == {"request_id": "grq_x", "status": "approved"}
    request = conn.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/v1/grant-requests/grq_x/approve"
    assert request["headers"]["X-Workspace-Key"] == "wsk_demo"
    assert json.loads(request["body"]) == {"decision_reason": "looks safe"}


def test_client_rejects_grant_request_with_decision_reason() -> None:
    client, conn = make_client(
        FakeResponse(200, {"request_id": "grq_x", "status": "rejected"})
    )

    body = client.reject_grant_request("grq_x", reason="out of policy")

    assert body == {"request_id": "grq_x", "status": "rejected"}
    request = conn.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/v1/grant-requests/grq_x/reject"
    assert request["headers"]["X-Workspace-Key"] == "wsk_demo"
    assert json.loads(request["body"]) == {"decision_reason": "out of policy"}


def test_client_revokes_grant_sends_no_body() -> None:
    client, conn = make_client(
        FakeResponse(200, {"grant_ref": "grt_x", "status": "revoked"})
    )

    body = client.revoke_grant("grt_x")

    assert body == {"grant_ref": "grt_x", "status": "revoked"}
    request = conn.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/v1/grants/grt_x/revoke"
    assert request["headers"]["X-Workspace-Key"] == "wsk_demo"
    assert request["body"] is None


def test_client_revoke_encodes_path_preventing_traversal() -> None:
    client, conn = make_client(FakeResponse(200, {"grant_ref": "x"}))

    client.revoke_grant("../../../healthz")

    path = conn.requests[0]["path"]
    assert path == "/v1/grants/..%2F..%2F..%2Fhealthz/revoke"
    assert "../" not in path


def test_client_issues_grant_sends_exact_body() -> None:
    client, conn = make_client(
        FakeResponse(
            201,
            {"grant_ref": "grt_x", "status": "active", "audit_event_id": "evt_issue"},
        )
    )

    body = client.issue_grant(
        agent_id="aid", scopes=["read:x/*"], ttl_seconds=3600
    )

    assert body == {
        "grant_ref": "grt_x",
        "status": "active",
        "audit_event_id": "evt_issue",
    }
    request = conn.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/v1/grants"
    assert request["headers"]["X-Workspace-Key"] == "wsk_demo"
    assert json.loads(request["body"]) == {
        "agent_id": "aid",
        "scopes": ["read:x/*"],
        "ttl_seconds": 3600,
    }


def test_client_approves_without_reason_sends_no_body() -> None:
    client, conn = make_client(FakeResponse(200, {"request_id": "grq_x"}))

    client.approve_grant_request("grq_x")

    request = conn.requests[0]
    assert request["method"] == "POST"
    assert request["path"] == "/v1/grant-requests/grq_x/approve"
    assert request["body"] is None


def test_client_approve_encodes_path_preventing_traversal() -> None:
    client, conn = make_client(FakeResponse(200, {"request_id": "x"}))

    client.approve_grant_request("../../../healthz", reason="ok")

    path = conn.requests[0]["path"]
    assert path == "/v1/grant-requests/..%2F..%2F..%2Fhealthz/approve"
    assert "../" not in path


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


def test_get_grant_url_encodes_path_preventing_traversal() -> None:
    """Path segments are URL-encoded (quote safe=""), so a traversal-looking
    grant_ref cannot escape the /v1/grants/ prefix."""
    client, conn = make_client(FakeResponse(200, {"grant_ref": "x"}))

    client.get_grant("../../../healthz")

    path = conn.requests[0]["path"]
    assert path == "/v1/grants/..%2F..%2F..%2Fhealthz"
    assert "../" not in path


def test_empty_path_value_is_rejected() -> None:
    """An empty path value is rejected before any request is issued."""
    client, _ = make_client(FakeResponse(200, {}))

    with pytest.raises(ValueError, match="non-empty"):
        client.get_grant("")


class RaisingConnection:
    """A connection that fails on request, simulating a down/unreachable service."""

    def __init__(self) -> None:
        self.closed = False

    def request(self, *args: Any, **kwargs: Any) -> None:
        raise ConnectionRefusedError("[Errno 61] Connection refused")

    def getresponse(self) -> Any:  # pragma: no cover - never reached
        raise AssertionError("getresponse should not be called after a failed request")

    def close(self) -> None:
        self.closed = True


def test_network_failure_fails_closed_without_exposing_credentials() -> None:
    """When the service is unreachable the error propagates (no result is
    returned — fail-closed), the connection is still closed, and the workspace
    key never appears in the surfaced error."""
    conn = RaisingConnection()
    client = VinctorServiceClient(
        endpoint="http://127.0.0.1:8765",
        workspace_key="wsk_demo",
        connection_factory=lambda host, port, timeout: conn,
    )

    with pytest.raises(ConnectionRefusedError) as error:
        client.get_grant("grt_demo")

    # propagates (no result returned), the connection is closed, and the
    # workspace key never appears in the surfaced error.
    assert conn.closed is True
    assert "wsk_demo" not in str(error.value)


# --- Real-socket fail-closed regressions (dogfood: a hung/unreachable upstream
# must never hang the caller). These exercise the *actual* default connection
# (real HTTPConnection honoring the configured timeout), not the fake factory,
# so they lock in the socket-level behavior the dogfood observed.


def _free_dead_port() -> int:
    """Bind a socket to grab a port, then release it so nothing listens there."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


@contextmanager
def _blackhole_listener() -> Iterator[int]:
    """A TCP listener that accepts connections but never sends a response,
    forcing the client into a read timeout (a hung upstream)."""
    stop = False
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen()
    server.settimeout(0.1)
    held: list[socket.socket] = []

    def run() -> None:
        while not stop:
            try:
                conn, _ = server.accept()
            except (TimeoutError, OSError):
                continue
            held.append(conn)  # keep the connection open but stay silent

    thread = Thread(target=run, daemon=True)
    thread.start()
    try:
        yield server.getsockname()[1]
    finally:
        stop = True
        for conn in held:
            conn.close()
        server.close()
        thread.join(timeout=5)


def test_dead_port_fails_closed_within_timeout() -> None:
    """A connection to a port with no listener fails closed (raises, no result)
    rather than hanging, and the workspace key never leaks in the error."""
    client = VinctorServiceClient(
        endpoint=f"http://127.0.0.1:{_free_dead_port()}",
        workspace_key="wsk_demo",
        timeout=2,
    )

    start = time.monotonic()
    with pytest.raises(OSError) as error:  # ConnectionRefused / timeout family
        client.get_grant("grt_demo")
    elapsed = time.monotonic() - start

    # Fails closed promptly (well within the timeout budget) and never returns.
    assert elapsed < 5
    assert "wsk_demo" not in str(error.value)


def test_hung_upstream_fails_closed_within_timeout() -> None:
    """A blackhole upstream that accepts but never responds must trip the
    read timeout and fail closed within the timeout budget — no hang."""
    with _blackhole_listener() as port:
        client = VinctorServiceClient(
            endpoint=f"http://127.0.0.1:{port}",
            workspace_key="wsk_demo",
            timeout=1,
        )

        start = time.monotonic()
        with pytest.raises((TimeoutError, OSError)) as error:
            client.get_grant("grt_demo")
        elapsed = time.monotonic() - start

    # The 1s read timeout fires; the caller fails closed without hanging
    # indefinitely, and the workspace key never appears in the error.
    assert 0.5 <= elapsed < 10
    assert "wsk_demo" not in str(error.value)
