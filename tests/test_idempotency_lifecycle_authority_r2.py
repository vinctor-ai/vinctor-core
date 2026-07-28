from __future__ import annotations

import base64
import inspect
import os
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import fields
from pathlib import Path

import pytest

from vinctor_service.idempotency_lifecycle import (
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
    IdempotencyLifecycleController,
    IdempotencyLifecycleRejected,
    IdempotencyRetirementRequest,
)
from vinctor_service.sqlite_txn import connect_sqlite


def test_lifecycle_rejection_survives_context_manager_reraise() -> None:
    @contextmanager
    def reraising_context() -> Iterator[None]:
        try:
            yield
        except IdempotencyLifecycleRejected:
            raise

    with (
        pytest.raises(IdempotencyLifecycleRejected, match="active_version_rejected"),
        reraising_context(),
    ):
        raise IdempotencyLifecycleRejected("active_version_rejected")


def _lifecycle_env(database: Path) -> dict[str, str]:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    active = base64.b64encode(b"a" * 32).decode("ascii")
    return {
        "VINCTOR_DB": str(database),
        "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (f'{{"active":"{active}","old":"{old}"}}'),
        "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "active",
    }


def test_public_lifecycle_surface_cannot_supply_time_or_result_count(
    tmp_path: Path,
) -> None:
    # Given the public facade and retirement request boundary.
    database = tmp_path / "public-authority.sqlite3"
    env = _lifecycle_env(database)
    facade_parameters = inspect.signature(IdempotencyLifecycleController.sqlite).parameters
    request_fields = {field.name for field in fields(IdempotencyRetirementRequest)}

    # When a caller inspects and attempts the former authority-bearing inputs.
    facade_accepted = True
    try:
        unexpected = IdempotencyLifecycleController.sqlite(
            database,
            env=env,
            **{"db_now_epoch": 4_102_444_800},
        )
    except TypeError:
        facade_accepted = False
    else:
        unexpected.close()
    request_accepted = True
    try:
        IdempotencyRetirementRequest(
            version="old",
            confirm_removal_window=True,
            **{"now_epoch": 4_102_444_800, "unexpired_result_count": 0},
        )
    except TypeError:
        request_accepted = False

    # Then neither public boundary can express caller time/count authority.
    assert "db_now_epoch" not in facade_parameters
    assert request_fields == {"version", "confirm_removal_window"}
    assert facade_accepted is False
    assert request_accepted is False


@pytest.mark.parametrize("flag", ("--now-epoch", "--unexpired-result-count"))
def test_installed_lifecycle_cli_rejects_authority_flags(
    tmp_path: Path,
    flag: str,
) -> None:
    # Given the real installed console script and an isolated configured database.
    database = tmp_path / f"cli-{flag[2:]}.sqlite3"
    executable = Path(sys.executable).with_name("vinctor")
    env = os.environ | _lifecycle_env(database) | {"PYTHONPATH": "src"}

    # When an operator attempts to supply time or count authority.
    completed = subprocess.run(
        (
            str(executable),
            "--db",
            str(database),
            "operator",
            "idempotency",
            "retire",
            "--version",
            "old",
            "--confirm-removal-window",
            flag,
            "4102444800",
        ),
        cwd=Path(__file__).parents[1],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    # Then argparse refuses the unknown flag before a lifecycle operation runs.
    rendered = completed.stdout + completed.stderr
    assert completed.returncode == 2
    assert "unrecognized arguments" in rendered
    assert env["VINCTOR_IDEMPOTENCY_KEYRING_JSON"] not in rendered


def test_sqlite_retirement_uses_database_time_and_current_unexpired_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an elapsed drain window but one old-version row unexpired by SQLite time.
    database = tmp_path / "database-authority.sqlite3"
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    )
    controller.write_disable(version="old", reason="rotation")
    controller.complete_drain(version="old", confirm_no_active_writers=True)
    connection = connect_sqlite(database)
    row = connection.execute("SELECT CAST(strftime('%s', 'now') AS INTEGER)").fetchone()
    assert row is not None
    database_now = int(row[0])
    connection.execute(
        "UPDATE idempotency_cipher_key_versions "
        "SET first_seen_epoch = ?, write_disabled_epoch = ?, "
        "drain_completed_epoch = ? "
        "WHERE version_label = ?",
        (
            database_now - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS - 2,
            database_now - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS - 1,
            database_now - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
            "old",
        ),
    )
    connection.execute(
        "INSERT INTO idempotency_results "
        "(workspace_id, principal, operation, key_hash, request_fingerprint, "
        "format_version, status_code, cipher_key_version, response_nonce, "
        "response_ciphertext, created_at_epoch, expires_at_epoch) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "ws",
            "agent:a",
            "grant.issue.v1",
            b"k" * 32,
            b"f" * 32,
            1,
            201,
            "old",
            b"n" * 12,
            b"ciphertext-and-tag",
            database_now,
            database_now + 3_600,
        ),
    )
    connection.commit()
    connection.close()
    monkeypatch.setattr(time, "time", lambda: database_now + 10 * 365 * 86_400)

    # When retirement is attempted while host time is far in the future.
    try:
        with pytest.raises(IdempotencyLifecycleRejected, match="unexpired_results_remain"):
            controller.retire(
                IdempotencyRetirementRequest(
                    version="old",
                    confirm_removal_window=True,
                )
            )

        # Then the authoritative database row remains unretired.
        assert controller.status("old").retired_epoch is None
    finally:
        controller.close()
