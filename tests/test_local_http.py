from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread
from typing import Any

from vinctor_core import BoundaryRegistrationInput, Grant, register_boundary
from vinctor_service import AgentIdentity, InMemoryV1Service, create_v1_http_server

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def service() -> InMemoryV1Service:
    return InMemoryV1Service(grants=(grant(),))


def identities() -> dict[str, AgentIdentity]:
    return {
        "agent_key_main": AgentIdentity(
            workspace_id="ws_main",
            agent_id="agent_release",
        )
    }


def body(
    *,
    grant_ref: str = "grt_main",
    action: str = "write",
    resource: str = "repo/feature/readme",
) -> dict[str, str]:
    return {"grant_ref": grant_ref, "action": action, "resource": resource}


@contextmanager
def running_server(service_instance: InMemoryV1Service) -> Iterator[ThreadingHTTPServer]:
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service_instance,
        agent_identities=identities(),
        clock=lambda: NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def post_json(
    server: ThreadingHTTPServer,
    *,
    payload: object = None,
    headers: dict[str, str] | None = None,
    path: str = "/v1/enforce",
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    request_headers = {
        "Content-Type": "application/json",
        **({"X-Agent-Key": "agent_key_main"} if headers is None else headers),
    }
    conn.request(
        "POST",
        path,
        body=json.dumps(body() if payload is None else payload),
        headers=request_headers,
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


def raw_request(
    server: ThreadingHTTPServer,
    *,
    method: str,
    request_body: str = "",
    headers: dict[str, str] | None = None,
    path: str = "/v1/enforce",
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    conn.request(
        method,
        path,
        body=request_body,
        headers=headers or {"X-Agent-Key": "agent_key_main"},
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


def test_local_http_service_permits_v1_enforce_request() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server)

    assert status == 200
    assert response["decision"] == "permit"
    assert response["grant_id"] == "grnt_main"
    assert response["agent_id"] == "agent_release"
    assert response["scope_matched"] == "write:repo/feature/*"
    assert len(svc.audit_events) == 1


def test_local_http_service_denies_and_records_audit() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(
            server,
            payload=body(action="send", resource="email/external"),
        )

    assert status == 403
    assert response["decision"] == "deny"
    assert response["error"] == "action_denied"
    assert len(svc.audit_events) == 1
    assert svc.audit_events[0].decision == "deny"


def test_local_http_service_keeps_v1_body_strict() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(
            server,
            payload={**body(), "boundary_id": "bnd_body"},
        )

    assert status == 400
    assert response["error"] == "invalid_request"
    assert svc.audit_events == ()


def test_local_http_service_rejects_invalid_json() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = raw_request(
            server,
            method="POST",
            request_body="{not-json",
            headers={"X-Agent-Key": "agent_key_main"},
        )

    assert status == 400
    assert response["error"] == "invalid_json"
    assert svc.audit_events == ()


def test_local_http_service_requires_agent_key() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server, headers={})

    assert status == 401
    assert response["error"] == "authentication_required"
    assert svc.audit_events == ()


def test_local_http_service_maps_boundary_header() -> None:
    svc = service()
    boundary = register_boundary(
        svc.boundary_registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_http",
    )

    with running_server(svc) as server:
        status, response = post_json(
            server,
            headers={
                "X-Agent-Key": "agent_key_main",
                "X-Vinctor-Boundary-Id": boundary.boundary_id,
            },
        )

    assert status == 200
    assert response["decision"] == "permit"
    assert svc.audit_events[0].boundary_id == "bnd_http"
    assert svc.audit_events[0].runtime == "claude-code"
    assert svc.audit_events[0].boundary_type == "pretooluse"


def test_local_http_service_returns_404_for_unknown_route() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = post_json(server, path="/v1/unknown")

    assert status == 404
    assert response["error"] == "not_found"
    assert svc.audit_events == ()


def test_local_http_service_requires_post_for_enforce() -> None:
    svc = service()

    with running_server(svc) as server:
        status, response = raw_request(server, method="GET")

    assert status == 405
    assert response["error"] == "method_not_allowed"
    assert svc.audit_events == ()
