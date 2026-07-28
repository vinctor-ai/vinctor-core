from __future__ import annotations

import io
import os
import sys

import pytest

from vinctor_mcp_server.server import create_stdio_server, main


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


class _BlockMcpImports:
    """Meta-path finder that makes ``mcp`` unimportable, as on a bare install."""

    def find_spec(self, fullname: str, path: object = None, target: object = None) -> None:
        if fullname == "mcp" or fullname.startswith("mcp."):
            raise ImportError(f"No module named {fullname!r}")
        return None


@pytest.fixture
def bare_install(monkeypatch: pytest.MonkeyPatch) -> None:
    """A install with no ``[mcp]`` extra and no ``VINCTOR_MCP_*`` configuration.

    The tests above pass ``create_server=boom``, so they assert only that
    ``main`` renders an error someone else raised — they cannot see which error
    the real code path raises first. These fixtures exercise the real
    ``create_stdio_server``.
    """
    for name in [n for n in sys.modules if n == "mcp" or n.startswith("mcp.")]:
        monkeypatch.delitem(sys.modules, name)
    monkeypatch.setattr(sys, "meta_path", [_BlockMcpImports(), *sys.meta_path])
    for name in [n for n in os.environ if n.startswith("VINCTOR_MCP_")]:
        monkeypatch.delenv(name, raising=False)


def test_bare_install_names_the_missing_extra_before_any_config_error(
    bare_install: None,
) -> None:
    """Without the extra, the SDK error must win over the env-var error.

    README: "Without the extra it exits with a clean one-line error". When
    config validation ran first, a bare install reported
    ``VINCTOR_MCP_ENDPOINT is required`` and never mentioned the extra, so the
    documented message appeared only once every variable happened to be set.
    """
    stderr = io.StringIO()

    with pytest.raises(SystemExit) as excinfo:
        main([], stderr=stderr)

    assert excinfo.value.code != 0
    text = stderr.getvalue()
    assert "error: MCP SDK is required to run vinctor-mcp-server." in text
    assert "vinctor-core[mcp]" in text
    # The whole point: the missing extra is not masked by a config error.
    assert "VINCTOR_MCP_ENDPOINT" not in text
    assert text.strip().count("\n") == 0, f"expected one line, got: {text!r}"
    assert "Traceback (most recent call last)" not in text


def test_create_stdio_server_raises_sdk_error_without_the_extra(bare_install: None) -> None:
    with pytest.raises(RuntimeError) as excinfo:
        create_stdio_server()

    assert "vinctor-core[mcp]" in str(excinfo.value)
