"""PKA-168: the unrecognized-``VINCTOR_*`` warning must actually reach an operator.

``test_env_registry_matches_sources.py`` pins WHICH names are unknown. This pins
that the warning is wired into the commands that start a server and lands on
stderr — the half a pure unit test cannot show, and the half that was missing:
the registry could be perfect and the operator still see nothing.

Every server-starting entry point is covered, across BOTH console scripts
`pyproject` ships. `service serve` is the deployed path where PKA-168 was found;
`local start` is the path in the README's quickstart, so it is the first place a
new operator would set a variable and the first place a typo would go unnoticed;
`vinctor-mcp-server` is a separate package that never reaches the CLI, so the
warning had to be wired there too (PKA-203) or half the artifact stayed silent.

The serve call is replaced with a sentinel raise, so the assertion is that the
warning is emitted BEFORE the server takes over — a warning printed after
`serve_forever()` would never appear until shutdown.
"""

from __future__ import annotations

import contextlib
import re
from io import StringIO
from pathlib import Path

import pytest

from vinctor_mcp_server.server import main as mcp_main
from vinctor_service import cli
from vinctor_service.cli import run_vinctor


class _Served(Exception):
    """Raised in place of serving, to stop the command at the right moment."""


def _run_serve(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr(
        cli, "serve_service_runtime", lambda config: (_ for _ in ()).throw(_Served())
    )
    stdout, stderr = StringIO(), StringIO()
    with contextlib.suppress(_Served):
        run_vinctor(
            ["service", "serve", "--db", str(tmp_path / "v.sqlite"), "--port", "0"],
            stdout=stdout,
            stderr=stderr,
        )
    return ""


def test_service_serve_warns_about_an_unknown_variable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("VINCTOR_AUDIT_SINK_REQUIRE", "true")  # the PKA-168 typo shape
    _run_serve(tmp_path, monkeypatch)

    err = capsys.readouterr().err
    assert "VINCTOR_AUDIT_SINK_REQUIRE" in err
    assert "not read by this build" in err


def test_service_serve_is_silent_when_every_name_is_known(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The positive control. Without it, a warning that fired unconditionally
    would pass every other test in this file."""
    for name in list(_vinctor_names(monkeypatch)):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("VINCTOR_AUDIT_SINK_REQUIRED", "false")
    monkeypatch.setenv("VINCTOR_LOG_LEVEL", "info")
    _run_serve(tmp_path, monkeypatch)

    assert "not read by this build" not in capsys.readouterr().err


def test_local_start_warns_too(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The quickstart path — where a new operator sets their first variable."""
    monkeypatch.setenv("VINCTOR_TYPOED_NAME", "1")
    monkeypatch.setattr(
        cli, "serve_local_service", lambda config: (_ for _ in ()).throw(_Served())
    )
    stdout, stderr = StringIO(), StringIO()
    with contextlib.suppress(_Served):
        run_vinctor(
            ["local", "start", "--db", str(tmp_path / "v.sqlite"), "--port", "0"],
            stdout=stdout,
            stderr=stderr,
        )

    assert "VINCTOR_TYPOED_NAME" in capsys.readouterr().err


def test_the_warning_does_not_refuse_startup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unknown variable must NEVER become a startup failure.

    An upgrade that crashes on a leftover variable is a worse outage than the
    silent no-op this warning exists to fix, and this process cannot know what
    else shares its environment. The sentinel proves the command reached the
    serve call rather than aborting earlier.
    """
    monkeypatch.setenv("VINCTOR_DEFINITELY_NOT_A_REAL_FLAG", "1")
    monkeypatch.setattr(
        cli, "serve_service_runtime", lambda config: (_ for _ in ()).throw(_Served())
    )
    stdout, stderr = StringIO(), StringIO()
    with pytest.raises(_Served):
        run_vinctor(
            ["service", "serve", "--db", str(tmp_path / "v.sqlite"), "--port", "0"],
            stdout=stdout,
            stderr=stderr,
        )


def test_mcp_server_warns_before_the_error_the_typo_caused(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """PKA-203, the reason this file now covers a second console script.

    The operator sets ``VINCTOR_MCP_ENDPOIN``, and the server tells them
    ``VINCTOR_MCP_ENDPOINT`` is required. Those two lines are one character
    apart and the second never mentions the first, so the operator reads it as
    "the variable I set was ignored" — PKA-168's exact failure, in the entry
    point its fix did not reach.

    Ordering carries the whole fix. The warning has to precede the error, or the
    operator sees the consequence with the cause nowhere on screen.
    """
    monkeypatch.setenv("VINCTOR_MCP_ENDPOIN", "http://127.0.0.1:9999")
    stderr = StringIO()

    def boom() -> object:
        raise ValueError("VINCTOR_MCP_ENDPOINT is required")

    with pytest.raises(SystemExit):
        mcp_main([], create_server=boom, stderr=stderr)

    text = stderr.getvalue()
    warning_line = next(line for line in text.splitlines() if "not read by this build" in line)
    # `\b` does not fire between `N` and `T`, so this cannot be satisfied by the
    # `VINCTOR_MCP_ENDPOINT` in the error line — the typo has to be named itself.
    assert re.search(r"\bVINCTOR_MCP_ENDPOIN\b", warning_line)
    assert text.index("not read by this build") < text.index("error: ")

    # stdout is this server's MCP protocol channel; a line here corrupts it.
    assert capsys.readouterr().out == ""


def test_mcp_server_still_starts_with_an_unknown_variable_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A warning, never a refusal — the same invariant the CLI holds.

    An MCP server that exited on a leftover variable would take the agent's
    whole tool surface down, which is far worse than the silent no-op the
    warning exists to report.
    """
    monkeypatch.setenv("VINCTOR_DEFINITELY_NOT_A_REAL_FLAG", "1")
    calls: list[str] = []

    class FakeServer:
        def run(self, *, transport: str) -> None:
            calls.append(transport)

    stderr = StringIO()
    result = mcp_main([], create_server=lambda: FakeServer(), stderr=stderr)

    assert result == 0
    assert calls == ["stdio"]
    assert "VINCTOR_DEFINITELY_NOT_A_REAL_FLAG" in stderr.getvalue()


def _vinctor_names(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    import os

    return [name for name in os.environ if name.startswith("VINCTOR_")]
