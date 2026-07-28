from __future__ import annotations

from io import StringIO
from pathlib import Path

import pytest

from vinctor_service.cli import EXIT_SERVICE, run_vinctor


def test_service_cli_reports_invalid_audit_sink_as_startup_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.delenv("VINCTOR_AUDIT_ANCHOR", raising=False)
    monkeypatch.delenv("VINCTOR_AUDIT_SINK_REQUIRED", raising=False)
    secret = "SUPERSECRET"
    monkeypatch.setenv(
        "VINCTOR_AUDIT_EXPORT",
        f"bad://{secret}/path?token=top-secret",
    )
    stdout = StringIO()
    stderr = StringIO()

    # When
    status = run_vinctor(
        [
            "service",
            "serve",
            "--db",
            str(tmp_path / "vinctor.sqlite"),
            "--port",
            "0",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    # Then
    assert status == EXIT_SERVICE
    assert "VINCTOR_AUDIT_EXPORT" in stderr.getvalue()
    assert secret not in stderr.getvalue()
    assert "top-secret" not in stderr.getvalue()
    assert "Traceback" not in stderr.getvalue()
    assert stdout.getvalue() == ""
