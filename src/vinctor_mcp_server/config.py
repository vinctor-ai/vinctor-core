from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class VinctorMcpConfig:
    endpoint: str
    workspace_key: str
    timeout: int = 5


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
    )


def _parse_timeout(value: str) -> int:
    try:
        timeout = int(value)
    except ValueError as error:
        raise ValueError("VINCTOR_MCP_TIMEOUT must be a positive integer") from error
    if timeout <= 0:
        raise ValueError("VINCTOR_MCP_TIMEOUT must be a positive integer")
    return timeout
