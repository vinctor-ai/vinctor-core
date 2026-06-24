from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path

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

    def approve_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, object]:
        return {"request_id": request_id, "status": "approved"}

    def reject_grant_request(
        self,
        request_id: str,
        *,
        reason: str | None = None,
    ) -> dict[str, object]:
        return {"request_id": request_id, "status": "rejected"}

    def revoke_grant(self, grant_ref: str) -> dict[str, object]:
        return {"grant_ref": grant_ref, "status": "revoked"}


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


def test_load_config_write_disabled_by_default() -> None:
    config = load_config(
        {
            "VINCTOR_MCP_ENDPOINT": "http://127.0.0.1:8765",
            "VINCTOR_MCP_WORKSPACE_KEY": "wsk_operator",
        }
    )

    assert config.write_enabled is False


def test_load_config_enables_write_for_truthy_values() -> None:
    for value in ("1", "true", "TRUE", "True"):
        config = load_config(
            {
                "VINCTOR_MCP_ENDPOINT": "http://127.0.0.1:8765",
                "VINCTOR_MCP_WORKSPACE_KEY": "wsk_operator",
                "VINCTOR_MCP_WRITE": value,
            }
        )

        assert config.write_enabled is True, value


def test_load_config_keeps_write_disabled_for_other_values() -> None:
    for value in ("0", "false", "no", ""):
        config = load_config(
            {
                "VINCTOR_MCP_ENDPOINT": "http://127.0.0.1:8765",
                "VINCTOR_MCP_WORKSPACE_KEY": "wsk_operator",
                "VINCTOR_MCP_WRITE": value,
            }
        )

        assert config.write_enabled is False, value


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


def test_create_stdio_server_omits_write_tools_when_write_disabled() -> None:
    server = create_stdio_server(
        config=VinctorMcpConfig(
            endpoint="http://127.0.0.1:8765",
            workspace_key="wsk_operator",
        ),
        client=FakeClient(),
        fastmcp_cls=FakeFastMcp,
    )

    assert "vinctor_approve_grant_request" not in server.tools
    assert "vinctor_reject_grant_request" not in server.tools
    assert "vinctor_revoke_grant" not in server.tools
    assert not any("approve" in name for name in server.tools)
    assert not any("reject" in name for name in server.tools)
    assert not any("revoke" in name for name in server.tools)


def test_create_stdio_server_registers_write_tools_when_write_enabled() -> None:
    server = create_stdio_server(
        config=VinctorMcpConfig(
            endpoint="http://127.0.0.1:8765",
            workspace_key="wsk_operator",
            write_enabled=True,
        ),
        client=FakeClient(),
        fastmcp_cls=FakeFastMcp,
    )

    assert "vinctor_approve_grant_request" in server.tools
    assert "vinctor_reject_grant_request" in server.tools
    assert "vinctor_revoke_grant" in server.tools


def test_server_module_entrypoint_invokes_main() -> None:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("VINCTOR_MCP_") and key != "VINCTOR_AGENT_KEY"
    }

    result = subprocess.run(
        [sys.executable, "-m", "vinctor_mcp_server.server"],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )

    assert result.returncode != 0
    assert "VINCTOR_MCP_ENDPOINT" in result.stderr
