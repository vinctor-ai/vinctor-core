"""Real stdio MCP integration tests for vinctor-mcp-server.

Unlike test_mcp_server.py / test_mcp_tools.py (in-process fakes), these tests
launch the actual ``vinctor-mcp-server`` as a subprocess and drive it as a real
MCP client over stdio. They exercise the transport, tool schemas, and the
allowlist output path end to end.

Ported from the dogfood harness in /tmp/vinctor_mcp_dogfood/harness.py.

Requires the optional ``mcp`` dependency (vinctor-core[mcp]); the module skips
cleanly when it is not installed.
"""

from __future__ import annotations

import asyncio
import importlib.metadata
import json
import os
import socket
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

import vinctor_mcp_server
from vinctor_core import Grant
from vinctor_service import AgentIdentity, InMemoryV1Service, WorkspaceIdentity
from vinctor_service.local_http import create_v1_http_server

# Skip the whole module if the MCP SDK is not available.
pytest.importorskip("mcp", reason="vinctor-core[mcp] not installed")
from mcp import ClientSession, StdioServerParameters  # noqa: E402
from mcp.client.stdio import stdio_client  # noqa: E402

NOW = datetime(2026, 6, 11, 12, 0, tzinfo=UTC)
SRC_ROOT = str(Path(vinctor_mcp_server.__file__).resolve().parent.parent)

EXPECTED_TOOLS = [
    "vinctor_boundary_report",
    "vinctor_explain_denial",
    "vinctor_get_audit_event",
    "vinctor_get_boundary",
    "vinctor_get_grant",
    "vinctor_get_grant_request",
    "vinctor_grant_report",
    "vinctor_grant_request_report",
    "vinctor_list_audit_events",
    "vinctor_list_auto_approval_rules",
    "vinctor_list_boundaries",
    "vinctor_list_grant_requests",
    "vinctor_list_grants",
    "vinctor_list_service_auth_failures",
    "vinctor_status",
]

# Substrings that must never appear anywhere in model-visible output.
FORBIDDEN_SUBSTRINGS = ("wsk_", "db_path", "key_hash", "raw_", "event_json")


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


def _email_grant() -> Grant:
    return Grant(
        grant_id="grnt_email",
        grant_ref="grt_email",
        workspace_id="ws_demo",
        agent_id="agent_demo",
        scopes=("send:email/*",),
        status="active",
        expires_at=None,
    )


@contextmanager
def _running_service() -> Iterator[int]:
    """Start an in-process vinctor-service on an ephemeral port; yield the port."""
    service = InMemoryV1Service(grants=(_grant(), _email_grant()))
    server = create_v1_http_server(
        ("127.0.0.1", 0),
        service=service,
        agent_identities={"aak_demo": AgentIdentity(workspace_id="ws_demo", agent_id="agent_demo")},
        workspace_identities={"wsk_demo": WorkspaceIdentity(workspace_id="ws_demo")},
        clock=lambda: NOW,
    )
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _enforce(port: int, action: str, resource: str) -> None:
    conn = HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(
            "POST",
            "/v1/enforce",
            body=json.dumps({"grant_ref": "grt_demo", "action": action, "resource": resource}),
            headers={"Content-Type": "application/json", "X-Agent-Key": "aak_demo"},
        )
        conn.getresponse().read()
    finally:
        conn.close()


def _server_params(port: int) -> StdioServerParameters:
    """Launch the real server via ``python -m vinctor_mcp_server`` (portable, no
    hard-coded venv path) and point it at the in-process service. PYTHONPATH is
    derived from the package location so the child imports work regardless of
    install form."""
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "vinctor_mcp_server"],
        env={
            **os.environ,
            "VINCTOR_MCP_ENDPOINT": f"http://127.0.0.1:{port}",
            "VINCTOR_MCP_WORKSPACE_KEY": "wsk_demo",
            "PYTHONPATH": os.pathsep.join(
                filter(None, [SRC_ROOT, os.environ.get("PYTHONPATH", "")])
            ),
        },
    )


def _server_params_with_env(port: int, extra_env: dict[str, str]) -> StdioServerParameters:
    params = _server_params(port)
    return StdioServerParameters(
        command=params.command,
        args=params.args,
        env={**(params.env or {}), **extra_env},
    )


def _server_params_with_timeout(port: int, timeout: int) -> StdioServerParameters:
    return _server_params_with_env(port, {"VINCTOR_MCP_TIMEOUT": str(timeout)})


@contextmanager
def _blackhole_service() -> Iterator[int]:
    stop = False
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("127.0.0.1", 0))
    server_socket.listen()
    server_socket.settimeout(0.1)

    def run() -> None:
        while not stop:
            try:
                conn, _ = server_socket.accept()
            except TimeoutError:
                continue
            with conn:
                while not stop:
                    try:
                        data = conn.recv(1024)
                    except OSError:
                        break
                    if not data:
                        break

    thread = Thread(target=run, daemon=True)
    thread.start()
    try:
        yield server_socket.getsockname()[1]
    finally:
        stop = True
        server_socket.close()
        thread.join(timeout=5)


def _tool_output(result: Any) -> Any:
    """Decode a tool result: prefer ``structuredContent``, else parse the first
    text block as JSON (MCP can return either shape)."""
    structured = getattr(result, "structuredContent", None)
    if structured:
        return structured
    for block in result.content:
        text = getattr(block, "text", None)
        if text is not None:
            return json.loads(text)
    return None


async def _with_session(port: int, body):  # body: async (session) -> T
    """Spawn the server, complete the MCP initialize handshake, then run ``body``
    against the live session. ``stdio_client`` owns the subprocess lifecycle."""
    params = _server_params(port)
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await asyncio.wait_for(session.initialize(), timeout=20)
        return await body(session)


def test_real_stdio_initialize_and_lists_only_read_only_tools() -> None:
    """Over real stdio: the server advertises exactly the read-only tools (see
    EXPECTED_TOOLS) and no mutate surface (approve/reject/revoke/issue/enforce)
    leaks through MCP."""

    async def body(session: ClientSession) -> None:
        listed = await asyncio.wait_for(session.list_tools(), timeout=20)
        names = sorted(t.name for t in listed.tools)
        assert names == EXPECTED_TOOLS
        # genuinely read-only: no mutate surface leaks over the wire
        assert not any(
            keyword in name
            for name in names
            for keyword in ("approve", "reject", "revoke", "issue", "enforce")
        )

    with _running_service() as port:
        asyncio.run(_with_session(port, body))


def test_real_stdio_tool_calls_return_allowlisted_output_only() -> None:
    """Over real stdio: calling the tools returns only allowlisted fields, and no
    forbidden substring (keys, db paths, raw payloads) appears anywhere in the
    model-visible output tree."""

    async def body(session: ClientSession) -> None:
        grant = _tool_output(
            await asyncio.wait_for(
                session.call_tool("vinctor_get_grant", {"grant_ref": "grt_demo"}), timeout=20
            )
        )
        assert grant["grant_ref"] == "grt_demo"
        assert "scopes" not in grant

        grants = _tool_output(
            await asyncio.wait_for(
                session.call_tool(
                    "vinctor_list_grants",
                    {"agent_id": "agent_demo", "status": "active"},
                ),
                timeout=20,
            )
        )
        assert [grant["grant_ref"] for grant in grants["grants"]] == [
            "grt_demo",
            "grt_email",
        ]
        assert all("scopes" not in grant for grant in grants["grants"])

        listed = _tool_output(
            await asyncio.wait_for(
                session.call_tool("vinctor_list_audit_events", {"limit": 5}), timeout=20
            )
        )
        events = listed["audit_events"]
        denial = next(e for e in events if e["decision"] == "deny")
        explained = _tool_output(
            await asyncio.wait_for(
                session.call_tool("vinctor_explain_denial", {"event_id": denial["event_id"]}),
                timeout=20,
            )
        )
        assert explained["decision"] == "deny"
        assert "missing_scope" not in explained
        assert "would_be_allowed_by" not in explained

        grant_requests = _tool_output(
            await asyncio.wait_for(session.call_tool("vinctor_list_grant_requests", {}), timeout=20)
        )
        assert grant_requests == {"grant_requests": []}

        rules = _tool_output(
            await asyncio.wait_for(
                session.call_tool("vinctor_list_auto_approval_rules", {}), timeout=20
            )
        )
        assert rules == {"auto_approval_rules": []}

        # nothing forbidden anywhere in any model-visible payload
        blob = json.dumps([grant, grants, listed, explained, grant_requests, rules])
        for forbidden in FORBIDDEN_SUBSTRINGS:
            assert forbidden not in blob

    with _running_service() as port:
        _enforce(port, "send", "email/external")  # one denial
        _enforce(port, "write", "repo/demo/readme")  # one permit
        asyncio.run(_with_session(port, body))


def test_real_stdio_diagnostic_mode_returns_authorization_hints() -> None:
    async def body(session: ClientSession) -> None:
        grant = _tool_output(
            await asyncio.wait_for(
                session.call_tool("vinctor_get_grant", {"grant_ref": "grt_demo"}), timeout=20
            )
        )
        assert grant["scopes"] == ["write:repo/demo/*"]

        listed = _tool_output(
            await asyncio.wait_for(
                session.call_tool("vinctor_list_audit_events", {"limit": 5}), timeout=20
            )
        )
        denial = next(e for e in listed["audit_events"] if e["decision"] == "deny")
        assert denial["scope_attempted"] == "send:email/external"

        explained = _tool_output(
            await asyncio.wait_for(
                session.call_tool("vinctor_explain_denial", {"event_id": denial["event_id"]}),
                timeout=20,
            )
        )
        assert explained["missing_scope"] == "send:email/external"
        assert explained["would_be_allowed_by"] == ["grt_email"]

    async def with_diagnostic_session(port: int) -> None:
        params = _server_params_with_env(port, {"VINCTOR_MCP_OUTPUT_MODE": "diagnostic"})
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=20)
            await body(session)

    with _running_service() as port:
        _enforce(port, "send", "email/external")
        asyncio.run(with_diagnostic_session(port))


def test_real_stdio_reports_vinctor_package_version() -> None:
    """serverInfo.version is the vinctor-core package version."""
    package_version = importlib.metadata.version("vinctor-core")

    async def init_only(port: int) -> str:
        params = _server_params(port)
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            result = await asyncio.wait_for(session.initialize(), timeout=20)
            return result.serverInfo.version

    with _running_service() as port:
        reported = asyncio.run(init_only(port))

    assert reported == package_version


def test_real_stdio_hanging_service_fails_closed_with_timeout() -> None:
    async def call_status(port: int) -> None:
        params = _server_params_with_timeout(port, 1)
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await asyncio.wait_for(session.initialize(), timeout=20)
            result = await asyncio.wait_for(session.call_tool("vinctor_status", {}), timeout=5)
            assert result.isError is True

    with _blackhole_service() as port:
        asyncio.run(call_status(port))
