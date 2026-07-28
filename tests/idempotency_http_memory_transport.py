from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO

from idempotency_http_fixtures import (
    AGENTS,
    NOW,
    WORKSPACES,
    JsonMutationPayload,
    RawResponse,
)

from vinctor_service import AgentIdentity, WorkspaceIdentity
from vinctor_service.local_http import create_v1_http_handler
from vinctor_service.v1_http import V1EnforceService


class MemoryConnection:
    def __init__(self, request: bytes) -> None:
        self._reader = BytesIO(request)
        self.output = bytearray()

    def makefile(self, mode: str, buffering: int = -1) -> BytesIO:
        del buffering
        assert mode == "rb"
        return self._reader

    def sendall(self, data: bytes) -> None:
        self.output.extend(data)

    def settimeout(self, timeout: float) -> None:
        del timeout


@dataclass(frozen=True, slots=True)
class MemoryServer:
    server_name: str = "localhost"
    server_port: int = 80


def post_memory_raw_json(
    service: V1EnforceService,
    path: str,
    body: bytes,
    headers: tuple[tuple[str, str], ...],
    *,
    agent_identities: Mapping[str, AgentIdentity] = AGENTS,
    workspace_identities: Mapping[str, WorkspaceIdentity] = WORKSPACES,
    request_now: datetime = NOW,
) -> RawResponse:
    request_lines = (
        f"POST {path} HTTP/1.1",
        "Host: localhost",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        *(f"{name}: {value}" for name, value in headers),
    )
    raw_request = "\r\n".join(request_lines).encode("iso-8859-1") + b"\r\n\r\n" + body
    connection = MemoryConnection(raw_request)
    handler = create_v1_http_handler(
        service=service,
        agent_identities=agent_identities,
        workspace_identities=workspace_identities,
        clock=lambda: request_now,
    )
    handler(connection, ("127.0.0.1", 1), MemoryServer())
    raw_headers, response_body = bytes(connection.output).split(b"\r\n\r\n", 1)
    header_lines = raw_headers.decode("iso-8859-1").split("\r\n")
    status_code = int(header_lines[0].split(" ", 2)[1])
    response_headers = {
        name.lower(): value.strip()
        for line in header_lines[1:]
        for name, value in (line.split(":", 1),)
    }
    return RawResponse(
        status_code=status_code,
        content_type=response_headers["content-type"],
        content_length=int(response_headers["content-length"]),
        body=response_body,
    )


def post_memory_json(
    service: V1EnforceService,
    path: str,
    payload: JsonMutationPayload,
    headers: Mapping[str, str],
) -> RawResponse:
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    return post_memory_raw_json(service, path, body, tuple(headers.items()))
