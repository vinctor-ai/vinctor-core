from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from vinctor_service.v1_http import (
    AgentIdentity,
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
    clock: Clock | None = None,
) -> ThreadingHTTPServer:
    handler = create_v1_http_handler(
        service=service,
        agent_identities=agent_identities,
        clock=clock,
    )
    return ThreadingHTTPServer(address, handler)


def create_v1_http_handler(
    *,
    service: V1EnforceService,
    agent_identities: Mapping[str, AgentIdentity],
    clock: Clock | None = None,
) -> type[BaseHTTPRequestHandler]:
    identities = dict(agent_identities)
    now = clock or _utc_now

    class V1Handler(BaseHTTPRequestHandler):
        server_version = "VinctorLocalHTTP/0.1"

        def do_POST(self) -> None:
            if urlsplit(self.path).path != "/v1/enforce":
                _send_json(
                    self,
                    V1HttpResponse(
                        status_code=404,
                        body={"error": "not_found", "reason": "route not found"},
                    ),
                )
                return

            parsed = _read_json_body(self)
            if isinstance(parsed, V1HttpResponse):
                _send_json(self, parsed)
                return

            response = handle_v1_enforce_http(
                headers=dict(self.headers.items()),
                body=parsed,
                agent_identities=identities,
                service=service,
                now=now(),
            )
            _send_json(self, response)

        def do_GET(self) -> None:
            _send_method_response(self)

        def do_PUT(self) -> None:
            _send_method_response(self)

        def do_PATCH(self) -> None:
            _send_method_response(self)

        def do_DELETE(self) -> None:
            _send_method_response(self)

        def log_message(self, format: str, *args: Any) -> None:
            return

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


def _send_method_response(handler: BaseHTTPRequestHandler) -> None:
    if urlsplit(handler.path).path == "/v1/enforce":
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

    _send_json(
        handler,
        V1HttpResponse(
            status_code=404,
            body={"error": "not_found", "reason": "route not found"},
        ),
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
