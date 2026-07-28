from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread

from vinctor_service import (
    AgentIdentity,
    GrantRequest,
    WorkspaceIdentity,
    create_v1_http_server,
)
from vinctor_service.v1_http import V1EnforceService

NOW = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
WORKSPACE_HEADERS = {"X-Workspace-Key": "workspace_key_main"}
AGENT_HEADERS = {"X-Agent-Key": "agent_key_main"}
WORKSPACES = {"workspace_key_main": WorkspaceIdentity(workspace_id="ws_main")}
AGENTS = {"agent_key_main": AgentIdentity(workspace_id="ws_main", agent_id="agent_release")}

JsonMutationPayload = dict[str, str | int | list[str]] | None


@dataclass(frozen=True, slots=True)
class RawResponse:
    status_code: int
    content_type: str
    content_length: int
    body: bytes


@contextmanager
def running_server(
    service: V1EnforceService,
    *,
    agent_identities: Mapping[str, AgentIdentity] = AGENTS,
    workspace_identities: Mapping[str, WorkspaceIdentity] = WORKSPACES,
) -> Iterator[ThreadingHTTPServer]:
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service,
        agent_identities=agent_identities,
        workspace_identities=workspace_identities,
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
    path: str,
    payload: JsonMutationPayload,
    headers: dict[str, str],
) -> RawResponse:
    host, port = server.server_address
    connection = HTTPConnection(host, port, timeout=5)
    connection.request(
        "POST",
        path,
        body="" if payload is None else json.dumps(payload),
        headers={"Content-Type": "application/json", **headers},
    )
    response = connection.getresponse()
    body = response.read()
    content_length = response.getheader("Content-Length")
    result = RawResponse(
        status_code=response.status,
        content_type=response.getheader("Content-Type") or "",
        content_length=int(content_length) if content_length is not None else -1,
        body=body,
    )
    connection.close()
    return result


def post_raw_json(
    server: ThreadingHTTPServer,
    path: str,
    body: bytes,
    headers: tuple[tuple[str, str], ...],
) -> RawResponse:
    host, port = server.server_address
    connection = HTTPConnection(host, port, timeout=5)
    connection.putrequest("POST", path)
    connection.putheader("Content-Type", "application/json")
    connection.putheader("Content-Length", str(len(body)))
    for name, value in headers:
        connection.putheader(name, value)
    connection.endheaders(body)
    response = connection.getresponse()
    response_body = response.read()
    content_length = response.getheader("Content-Length")
    result = RawResponse(
        status_code=response.status,
        content_type=response.getheader("Content-Type") or "",
        content_length=int(content_length) if content_length is not None else -1,
        body=response_body,
    )
    connection.close()
    return result


def pending_request(request_id: str, *, scopes: tuple[str, ...]) -> GrantRequest:
    return GrantRequest(
        request_id=request_id,
        workspace_id="ws_main",
        requester_agent_id="agent_release",
        target_agent_id="agent_release",
        requested_scopes=scopes,
        requested_ttl_seconds=3600,
        reason="pin legacy decision semantics",
        status="pending",
        created_at=NOW,
    )
