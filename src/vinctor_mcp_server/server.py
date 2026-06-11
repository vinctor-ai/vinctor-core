from __future__ import annotations

from importlib.metadata import version
from inspect import signature
from typing import Any

from vinctor_mcp_server.config import VinctorMcpConfig, load_config
from vinctor_mcp_server.service_client import VinctorServiceClient
from vinctor_mcp_server.tools import ReadOnlyVinctorClient, register_read_only_tools


def create_stdio_server(
    *,
    config: VinctorMcpConfig | None = None,
    client: ReadOnlyVinctorClient | None = None,
    fastmcp_cls: type[Any] | None = None,
) -> Any:
    resolved_config = config or load_config()
    resolved_client = client or VinctorServiceClient(
        endpoint=resolved_config.endpoint,
        workspace_key=resolved_config.workspace_key,
        timeout=resolved_config.timeout,
    )
    server_cls = fastmcp_cls or _load_fastmcp()
    mcp = _create_fastmcp(server_cls, "vinctor-mcp-server", version("vinctor-core"))
    register_read_only_tools(mcp, resolved_client)
    return mcp


def main() -> None:
    mcp = create_stdio_server()
    mcp.run(transport="stdio")


def _load_fastmcp() -> type[Any]:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as error:
        raise RuntimeError(
            "MCP SDK is required to run vinctor-mcp-server. "
            'Install with vinctor-core[mcp].'
        ) from error
    return FastMCP


def _create_fastmcp(server_cls: type[Any], name: str, server_version: str) -> Any:
    if "version" in signature(server_cls).parameters:
        return server_cls(name, version=server_version)
    mcp = server_cls(name)
    low_level_server = getattr(mcp, "_mcp_server", None)
    if low_level_server is not None and hasattr(low_level_server, "version"):
        low_level_server.version = server_version
    return mcp
