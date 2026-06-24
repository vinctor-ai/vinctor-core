from __future__ import annotations

import io

import pytest

from vinctor_mcp_server.server import main


def test_main_help_exits_zero_and_prints_usage(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])

    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "vinctor-mcp-server" in captured.out
    assert "Traceback (most recent call last)" not in captured.out
    assert "Traceback (most recent call last)" not in captured.err


def test_main_config_error_prints_clean_line_and_exits_nonzero() -> None:
    stderr = io.StringIO()

    def boom() -> object:
        raise ValueError("VINCTOR_MCP_ENDPOINT is required")

    with pytest.raises(SystemExit) as excinfo:
        main([], create_server=boom, stderr=stderr)

    assert excinfo.value.code != 0
    text = stderr.getvalue()
    assert "error: VINCTOR_MCP_ENDPOINT is required" in text
    assert "Traceback (most recent call last)" not in text


def test_main_sdk_missing_error_prints_clean_line_and_exits_nonzero() -> None:
    stderr = io.StringIO()

    def boom() -> object:
        raise RuntimeError("MCP SDK is required to run vinctor-mcp-server.")

    with pytest.raises(SystemExit) as excinfo:
        main([], create_server=boom, stderr=stderr)

    assert excinfo.value.code != 0
    text = stderr.getvalue()
    assert "error: MCP SDK is required to run vinctor-mcp-server." in text
    assert "Traceback (most recent call last)" not in text


def test_main_happy_path_runs_stdio_server() -> None:
    calls: list[str] = []

    class FakeServer:
        def run(self, *, transport: str) -> None:
            calls.append(transport)

    server = FakeServer()
    result = main([], create_server=lambda: server)

    assert result == 0
    assert calls == ["stdio"]
