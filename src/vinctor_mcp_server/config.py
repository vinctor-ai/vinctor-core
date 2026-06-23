from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

from vinctor_mcp_server.output_policy import OutputMode


@dataclass(frozen=True)
class VinctorMcpConfig:
    endpoint: str
    workspace_key: str
    timeout: int = 5
    output_mode: OutputMode = "safe"
    write_enabled: bool = False


def load_config(env: Mapping[str, str] | None = None) -> VinctorMcpConfig:
    values = env or os.environ
    endpoint = values.get("VINCTOR_MCP_ENDPOINT")
    workspace_key = values.get("VINCTOR_MCP_WORKSPACE_KEY")
    if endpoint is None or endpoint == "":
        raise ValueError("VINCTOR_MCP_ENDPOINT is required")
    if workspace_key is None or workspace_key == "":
        raise ValueError("VINCTOR_MCP_WORKSPACE_KEY is required")
    return VinctorMcpConfig(
        endpoint=endpoint,
        workspace_key=workspace_key,
        timeout=_parse_timeout(values.get("VINCTOR_MCP_TIMEOUT", "5")),
        output_mode=_parse_output_mode(values.get("VINCTOR_MCP_OUTPUT_MODE", "safe")),
        write_enabled=_parse_truthy(values.get("VINCTOR_MCP_WRITE", "")),
    )


def _parse_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as error:
        raise ValueError("VINCTOR_MCP_TIMEOUT must be a positive integer") from error
    if timeout <= 0:
        raise ValueError("VINCTOR_MCP_TIMEOUT must be a positive integer")
    return timeout


def _parse_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true"}


def _parse_output_mode(value: str) -> OutputMode:
    if value not in {"safe", "diagnostic"}:
        raise ValueError("VINCTOR_MCP_OUTPUT_MODE must be safe or diagnostic")
    return value
