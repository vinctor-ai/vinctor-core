from __future__ import annotations

import io
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from threading import Thread

from vinctor_core import Grant
from vinctor_service import (
    AgentIdentity,
    InMemoryV1Service,
    create_v1_http_server,
)

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


def body() -> dict[str, str]:
    return {
        "grant_ref": "grt_main",
        "action": "write",
        "resource": "repo/feature/readme",
    }


@contextmanager
def running_server(
    service_instance: InMemoryV1Service,
    *,
    access_log: bool = False,
) -> Iterator[ThreadingHTTPServer]:
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service_instance,
        agent_identities=identities(),
        clock=lambda: NOW,
        access_log=access_log,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def post_enforce(server: ThreadingHTTPServer) -> int:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    conn.request(
        "POST",
        "/v1/enforce",
        body=json.dumps(body()),
        headers={
            "Content-Type": "application/json",
            "X-Agent-Key": "agent_key_main",
        },
    )
    response = conn.getresponse()
    response.read()
    conn.close()
    return response.status


def test_access_log_emits_one_leak_free_json_line(monkeypatch) -> None:
    captured = io.StringIO()
    monkeypatch.setattr("sys.stderr", captured)

    svc = service()
    with running_server(svc, access_log=True) as server:
        status = post_enforce(server)

    assert status == 200
    lines = [line for line in captured.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert set(record) == {
        "ts",
        "method",
        "path",
        "status",
        "latency_ms",
        "decision",
    }
    assert record["method"] == "POST"
    assert record["path"] == "/v1/enforce"
    assert record["status"] == 200
    assert record["decision"] == "permit"
    assert isinstance(record["latency_ms"], int | float)

    # Leak-free: never an agent key, grant ref, agent id, workspace id, or any
    # raw body value.
    raw = captured.getvalue()
    for secret in (
        "agent_key_main",
        "grt_main",
        "grnt_main",
        "agent_release",
        "ws_main",
        "repo/feature/readme",
    ):
        assert secret not in raw


def test_access_log_off_emits_nothing(monkeypatch) -> None:
    captured = io.StringIO()
    monkeypatch.setattr("sys.stderr", captured)

    svc = service()
    with running_server(svc, access_log=False) as server:
        status = post_enforce(server)

    assert status == 200
    assert captured.getvalue() == ""
