from __future__ import annotations

from collections.abc import Callable
from importlib.metadata import version

import pytest

from vinctor_mcp_server.config import VinctorMcpConfig, load_config
from vinctor_mcp_server.server import create_stdio_server


class FakeFastMcp:
    def __init__(self, name: str, *, version: str) -> None:
        self.name = name
        self.version = version
        self.tools: dict[str, Callable[..., object]] = {}

    def tool(self, *, name: str, description: str) -> Callable[[Callable[..., object]], object]:
        def register(fn: Callable[..., object]) -> object:
            self.tools[name] = fn
            return fn

        return register


class FakeClient:
    def status(self) -> dict[str, object]:
        return {"status": "ok", "service": "vinctor-service", "mode": "local"}

    def list_boundaries(self) -> dict[str, object]:
        return {"boundaries": []}

    def get_boundary(self, boundary_id: str) -> dict[str, object]:
        return {"boundary_id": boundary_id}

    def get_grant(self, grant_ref: str) -> dict[str, object]:
        return {"grant_ref": grant_ref}

    def list_grants(
        self,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> dict[str, object]:
        return {"grants": []}

    def list_grant_requests(self) -> dict[str, object]:
        return {"grant_requests": []}

    def get_grant_request(self, request_id: str) -> dict[str, object]:
        return {"request_id": request_id}

    def list_auto_approval_rules(self) -> dict[str, object]:
        return {"auto_approval_rules": []}


def test_load_config_requires_mcp_workspace_key_not_agent_key() -> None:
    with pytest.raises(ValueError, match="VINCTOR_MCP_WORKSPACE_KEY"):
        load_config(
            {
                "VINCTOR_MCP_ENDPOINT": "http://127.0.0.1:8765",
                "VINCTOR_AGENT_KEY": "aak_runtime",
            }
        )


def test_load_config_reads_explicit_mcp_environment() -> None:
    config = load_config(
        {
            "VINCTOR_MCP_ENDPOINT": "http://127.0.0.1:8765",
            "VINCTOR_MCP_WORKSPACE_KEY": "wsk_operator",
            "VINCTOR_MCP_TIMEOUT": "9",
            "VINCTOR_MCP_OUTPUT_MODE": "diagnostic",
        }
    )

    assert config == VinctorMcpConfig(
        endpoint="http://127.0.0.1:8765",
        workspace_key="wsk_operator",
        timeout=9,
        output_mode="diagnostic",
    )


def test_load_config_rejects_unknown_output_mode() -> None:
    with pytest.raises(ValueError, match="VINCTOR_MCP_OUTPUT_MODE"):
        load_config(
            {
                "VINCTOR_MCP_ENDPOINT": "http://127.0.0.1:8765",
                "VINCTOR_MCP_WORKSPACE_KEY": "wsk_operator",
                "VINCTOR_MCP_OUTPUT_MODE": "debug",
            }
        )


def test_create_stdio_server_registers_read_only_tools_with_fastmcp() -> None:
    server = create_stdio_server(
        config=VinctorMcpConfig(
            endpoint="http://127.0.0.1:8765",
            workspace_key="wsk_operator",
        ),
        client=FakeClient(),
        fastmcp_cls=FakeFastMcp,
    )

    assert server.name == "vinctor-mcp-server"
    assert server.version == version("vinctor-core")
    assert sorted(server.tools) == [
        "vinctor_explain_denial",
        "vinctor_get_audit_event",
        "vinctor_get_boundary",
        "vinctor_get_grant",
        "vinctor_get_grant_request",
        "vinctor_list_audit_events",
        "vinctor_list_auto_approval_rules",
        "vinctor_list_boundaries",
        "vinctor_list_grant_requests",
        "vinctor_list_grants",
        "vinctor_status",
    ]
