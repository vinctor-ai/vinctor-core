from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlsplit

from vinctor_service.boundary_http import (
    BoundaryAdminService,
    WorkspaceIdentity,
    WorkspaceIdentityResolver,
    handle_v1_boundaries_http,
)
from vinctor_service.v1_http import (
    AgentIdentity,
    AgentIdentityResolver,
    V1EnforceService,
    V1HttpResponse,
    handle_v1_enforce_http,
)

Clock = Callable[[], datetime]


def create_v1_http_server(
    address: tuple[str, int],
    *,
    service: V1EnforceService,
    agent_identities: Mapping[str, AgentIdentity],
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    clock: Clock | None = None,
) -> ThreadingHTTPServer:
    handler = create_v1_http_handler(
        service=service,
        agent_identities=agent_identities,
        workspace_identities=workspace_identities,
        agent_identity_resolver=agent_identity_resolver,
        workspace_identity_resolver=workspace_identity_resolver,
        clock=clock,
    )
    return ThreadingHTTPServer(address, handler)


def create_v1_http_handler(
    *,
    service: V1EnforceService,
    agent_identities: Mapping[str, AgentIdentity],
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    clock: Clock | None = None,
) -> type[BaseHTTPRequestHandler]:
    agent_keys = dict(agent_identities)
    workspace_keys = dict(workspace_identities or {})
    now = clock or _utc_now

    class V1Handler(BaseHTTPRequestHandler):
        server_version = "VinctorLocalHTTP/0.1"

        def do_POST(self) -> None:
            _handle_request(self, "POST")

        def do_GET(self) -> None:
            _handle_request(self, "GET")

        def do_PUT(self) -> None:
            _handle_request(self, "PUT")

        def do_PATCH(self) -> None:
            _handle_request(self, "PATCH")

        def do_DELETE(self) -> None:
            _handle_request(self, "DELETE")

        def log_message(self, format: str, *args: Any) -> None:
            return

    def _handle_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        path = urlsplit(handler.path).path
        if path == "/v1/enforce":
            _handle_enforce_request(handler, method)
            return
        if path == "/v1/boundaries" or path.startswith("/v1/boundaries/"):
            _handle_boundary_request(handler, method, path)
            return

        _send_json(
            handler,
            V1HttpResponse(
                status_code=404,
                body={"error": "not_found", "reason": "route not found"},
            ),
        )

    def _handle_enforce_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        if method != "POST":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "POST is required for /v1/enforce",
                    },
                ),
            )
            return

        parsed = _read_json_body(handler)
        if isinstance(parsed, V1HttpResponse):
            _send_json(handler, parsed)
            return

        response = handle_v1_enforce_http(
            headers=dict(handler.headers.items()),
            body=parsed,
            agent_identities=agent_keys,
            agent_identity_resolver=agent_identity_resolver,
            service=service,
            now=now(),
        )
        _send_json(handler, response)

    def _handle_boundary_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
    ) -> None:
        body: object = None
        if method == "POST" and path == "/v1/boundaries":
            parsed = _read_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        response = handle_v1_boundaries_http(
            method=method,
            path=path,
            headers=dict(handler.headers.items()),
            body=body,
            workspace_identities=workspace_keys,
            workspace_identity_resolver=workspace_identity_resolver,
            service=cast(BoundaryAdminService, service),
            now=now(),
        )
        _send_json(handler, response)

    return V1Handler


def _read_json_body(handler: BaseHTTPRequestHandler) -> object | V1HttpResponse:
    length_header = handler.headers.get("Content-Length")
    try:
        length = int(length_header or "0")
    except ValueError:
        return V1HttpResponse(
            status_code=400,
            body={
                "error": "invalid_request",
                "reason": "Content-Length must be an integer",
            },
        )

    raw_body = handler.rfile.read(length)
    try:
        return json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return V1HttpResponse(
            status_code=400,
            body={
                "error": "invalid_json",
                "reason": "request body must be valid JSON",
            },
        )


def _send_json(handler: BaseHTTPRequestHandler, response: V1HttpResponse) -> None:
    payload = json.dumps(response.body, sort_keys=True).encode("utf-8")
    handler.send_response(response.status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _utc_now() -> datetime:
    return datetime.now(UTC)
