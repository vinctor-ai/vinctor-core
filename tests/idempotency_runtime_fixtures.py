from __future__ import annotations

import base64
from dataclasses import dataclass
from io import StringIO
from pathlib import Path

import pytest

from vinctor_service.cli import run_vinctor

KEYS_ENV = "VINCTOR_IDEMPOTENCY_KEYRING_JSON"
ACTIVE_ENV = "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION"


def configured_env(database: Path) -> dict[str, str]:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    primary = base64.b64encode(b"p" * 32).decode("ascii")
    return {
        "VINCTOR_DB": str(database),
        KEYS_ENV: f'{{"old":"{old}","primary":"{primary}"}}',
        ACTIVE_ENV: "primary",
    }


def configured_secret_values(env: dict[str, str]) -> tuple[str, ...]:
    return (
        env[KEYS_ENV],
        base64.b64encode(b"o" * 32).decode("ascii"),
        base64.b64encode(b"p" * 32).decode("ascii"),
    )


@dataclass(frozen=True, slots=True)
class ReadinessCase:
    name: str
    active_disabled: bool = False
    active_retired: bool = False
    reserved_slots: int = 0
    nonce_count: int = 0


READINESS_CASES = (
    ReadinessCase("active-disabled", active_disabled=True),
    ReadinessCase("active-retired", active_retired=True),
    ReadinessCase("count-mismatch", reserved_slots=1),
    ReadinessCase("hard-limit-overflow", reserved_slots=(2**24) + 1, nonce_count=(2**24) + 1),
)


@dataclass(frozen=True, slots=True)
class CliRedactionOutcome:
    success: int
    failure: int
    rendered: str
    failure_stderr: str
    secrets: tuple[str, ...]


def exercise_old_version_cli_rejections(
    database: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[int, int]:
    env = configured_env(database)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    stderr = StringIO()
    missing = run_vinctor(
        ["--db", env["VINCTOR_DB"], "operator", "idempotency", "write-disable"],
        stderr=stderr,
    )
    active = run_vinctor(
        [
            "--db",
            env["VINCTOR_DB"],
            "operator",
            "idempotency",
            "write-disable",
            "--version",
            "primary",
            "--reason",
            "rotation",
        ],
        stderr=stderr,
    )
    return missing, active


def exercise_cli_redaction(
    database: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> CliRedactionOutcome:
    env = configured_env(database)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    success_stdout, success_stderr = StringIO(), StringIO()
    success = run_vinctor(
        ["--db", str(database), "operator", "idempotency", "status"],
        stdout=success_stdout,
        stderr=success_stderr,
    )
    dsn = "postgresql://operator:dsn-secret@127.0.0.1:1/vinctor_secret"
    monkeypatch.setenv("VINCTOR_STORAGE_BACKEND", "postgres")
    monkeypatch.setenv("VINCTOR_POSTGRES_DSN", dsn)
    failure_stdout, failure_stderr = StringIO(), StringIO()
    failure = run_vinctor(
        ["operator", "idempotency", "status"],
        stdout=failure_stdout,
        stderr=failure_stderr,
    )
    return CliRedactionOutcome(
        success=success,
        failure=failure,
        rendered="".join(
            (
                success_stdout.getvalue(),
                success_stderr.getvalue(),
                failure_stdout.getvalue(),
                failure_stderr.getvalue(),
            )
        ),
        failure_stderr=failure_stderr.getvalue(),
        secrets=(*configured_secret_values(env), dsn, "dsn-secret", "vinctor_secret"),
    )
