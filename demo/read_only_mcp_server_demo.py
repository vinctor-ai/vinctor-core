from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread
from typing import Any

from vinctor_core import Grant
from vinctor_mcp_server.service_client import VinctorServiceClient
from vinctor_mcp_server.tools import VinctorReadOnlyTools
from vinctor_service import AgentIdentity, InMemoryV1Service, WorkspaceIdentity
from vinctor_service.local_http import create_v1_http_server

NOW = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)


def main() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    with _running_server(svc) as server:
        _create_denied_audit_event(server)
        host, port = server.server_address
        client = VinctorServiceClient(
            endpoint=f"http://{host}:{port}",
            workspace_key="wsk_demo",
        )
        tools = VinctorReadOnlyTools(client)

        status = tools.status()
        audit = tools.list_audit_events(limit=5, event_type="action_denied")
        event_id = audit["audit_events"][0]["event_id"]
        explanation = tools.explain_denial(event_id)

    _assert_no_disallowed_fields(audit["audit_events"][0])
    _assert_no_disallowed_fields(explanation)
    print(
        json.dumps(
            {
                "status": status,
                "audit_event_count": len(audit["audit_events"]),
                "denial_reason": explanation["reason"],
                "denial_explanation": explanation["explanation"],
            },
            sort_keys=True,
        )
    )


def _grant() -> Grant:
    return Grant(
        grant_id="grnt_demo",
        grant_ref="grt_demo",
        workspace_id="ws_demo",
        agent_id="agent_demo",
        scopes=("write:repo/demo/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


@contextmanager
def _running_server(service: InMemoryV1Service) -> Iterator[ThreadingHTTPServer]:
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service,
        agent_identities={
            "aak_demo": AgentIdentity(workspace_id="ws_demo", agent_id="agent_demo")
        },
        workspace_identities={"wsk_demo": WorkspaceIdentity(workspace_id="ws_demo")},
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


def _create_denied_audit_event(server: ThreadingHTTPServer) -> None:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.request(
            "POST",
            "/v1/enforce",
            body=json.dumps(
                {
                    "grant_ref": "grt_demo",
                    "action": "send",
                    "resource": "email/external",
                }
            ),
            headers={"Content-Type": "application/json", "X-Agent-Key": "aak_demo"},
        )
        response = conn.getresponse()
        response.read()
        if response.status != 403:
            raise RuntimeError(f"expected deny response, got {response.status}")
    finally:
        conn.close()


def _assert_no_disallowed_fields(value: dict[str, Any]) -> None:
    disallowed = {
        "event_json",
        "raw_prompt",
        "raw_tool_input",
        "raw_command",
        "raw_key",
        "key_hash",
        "db_path",
    }
    leaked = sorted(disallowed & set(value))
    if leaked:
        raise RuntimeError(f"model-visible output leaked disallowed fields: {leaked}")


if __name__ == "__main__":
    main()
