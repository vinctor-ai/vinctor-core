from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Callable
from importlib.metadata import version
from inspect import signature
from typing import Any, TextIO

from vinctor_mcp_server.config import VinctorMcpConfig, load_config
from vinctor_mcp_server.service_client import VinctorServiceClient
from vinctor_mcp_server.tools import (
    ReadOnlyVinctorClient,
    register_read_only_tools,
    register_write_tools,
)
from vinctor_service.env_registry import unrecognized_env_warning


def create_stdio_server(
    *,
    config: VinctorMcpConfig | None = None,
    client: ReadOnlyVinctorClient | None = None,
    fastmcp_cls: type[Any] | None = None,
) -> Any:
    # The SDK check runs BEFORE config validation on purpose. Without the [mcp]
    # extra this command cannot run under any configuration, so reporting a
    # missing env var first sends the operator to fix the wrong thing — and the
    # real cause only surfaces once every variable happens to be set.
    server_cls = fastmcp_cls or _load_fastmcp()
    resolved_config = config or load_config()
    resolved_client = client or VinctorServiceClient(
        endpoint=resolved_config.endpoint,
        workspace_key=resolved_config.workspace_key,
        service_operator_key=resolved_config.service_operator_key,
        timeout=resolved_config.timeout,
    )
    mcp = _create_fastmcp(server_cls, "vinctor-mcp-server", version("vinctor-core"))
    register_read_only_tools(mcp, resolved_client, output_mode=resolved_config.output_mode)
    if resolved_config.write_enabled:
        register_write_tools(mcp, resolved_client, output_mode=resolved_config.output_mode)
    return mcp


def main(
    argv: list[str] | None = None,
    *,
    create_server: Callable[[], Any] = create_stdio_server,
    stderr: TextIO = sys.stderr,
) -> int:
    _parser().parse_args(argv)
    _warn_unrecognized_env(stderr)
    try:
        mcp = create_server()
    except (ValueError, RuntimeError) as error:
        print(f"error: {error}", file=stderr)
        raise SystemExit(1) from None
    mcp.run(transport="stdio")
    return 0


def _warn_unrecognized_env(stderr: TextIO) -> None:
    """PKA-203: this console script needs PKA-168's warning too.

    ``pyproject`` ships TWO entry points. The warning was wired only into
    ``vinctor_service.cli``, and this package never reaches it, so the build's
    other command stayed silent — an operator who set ``VINCTOR_MCP_ENDPOIN``
    was told ``VINCTOR_MCP_ENDPOINT`` is required and never told the typo was
    sitting next to it. That is PKA-168's "I set it and nothing happened"
    verbatim, in the half of the artifact the original fix did not cover.

    Emitted BEFORE ``create_server()``, which raises on the first missing or
    invalid variable. After it, the process is already exiting and the operator
    would see only the consequence, never the cause. It stays a warning and
    never a refusal, for the same reason as the CLI's copy: the environment is
    shared and a leftover name must not become an outage.

    stderr, never stdout. This server speaks the MCP protocol over stdout, so a
    line printed there would not merely be noise — it would corrupt the channel.
    """
    warning = unrecognized_env_warning(os.environ)
    if warning is not None:
        print(warning, file=stderr, flush=True)


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="vinctor-mcp-server",
        description="Run the Vinctor MCP stdio server.",
    )


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


if __name__ == "__main__":
    main()
