from __future__ import annotations

from pathlib import Path

import pytest
from idempotency_runtime_fixtures import (
    configured_env as _configured_env,
)
from idempotency_runtime_fixtures import (
    exercise_cli_redaction,
    exercise_old_version_cli_rejections,
)

from vinctor_service.sqlite_txn import connect_sqlite


def test_rotation_disables_explicit_old_version_and_blocks_post_barrier_reservation(
    tmp_path: Path,
) -> None:
    from vinctor_service.idempotency_lifecycle import IdempotencyLifecycleController

    controller = IdempotencyLifecycleController.sqlite(
        tmp_path / "rotation.sqlite3",
        env=_configured_env(tmp_path / "rotation.sqlite3"),
    )
    controller.write_disable(version="old", reason="rotation")
    with pytest.raises(RuntimeError):
        controller.reserve_nonce(version="old")

def test_drain_completed_cannot_precede_external_drain_confirmation(tmp_path: Path) -> None:
    from vinctor_service.idempotency_lifecycle import IdempotencyLifecycleController

    database = tmp_path / "drain.sqlite3"
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_configured_env(database),
    )
    controller.write_disable(version="old", reason="rotation")
    with pytest.raises(ValueError):
        controller.complete_drain(version="old", confirm_no_active_writers=False)

def test_retirement_waits_for_drain_plus_86400_plus_300_and_zero_unexpired_results(
    tmp_path: Path,
) -> None:
    from vinctor_service.idempotency_lifecycle import (
        IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
        IdempotencyLifecycleController,
        IdempotencyRetirementRequest,
    )

    database = tmp_path / "retire.sqlite3"
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_configured_env(database),
    )
    controller.write_disable(version="old", reason="rotation")
    controller.complete_drain(version="old", confirm_no_active_writers=True)
    request = IdempotencyRetirementRequest(
        version="old",
        confirm_removal_window=True,
    )
    with pytest.raises(ValueError, match="removal_window_not_elapsed"):
        controller.retire(request)

    connection = connect_sqlite(database)
    row = connection.execute("SELECT CAST(strftime('%s', 'now') AS INTEGER)").fetchone()
    assert row is not None
    database_now = int(row[0])
    connection.execute(
        "UPDATE idempotency_cipher_key_versions "
        "SET first_seen_epoch = ?, write_disabled_epoch = ?, "
        "drain_completed_epoch = ? WHERE version_label = ?",
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
    with pytest.raises(ValueError, match="unexpired_results_remain"):
        controller.retire(request)
    connection.execute(
        "DELETE FROM idempotency_results WHERE cipher_key_version = ?",
        ("old",),
    )
    connection.commit()
    connection.close()

    controller.retire(request)
    assert controller.status("old").retired_epoch is not None

def test_startup_never_deletes_or_decrements_old_nonce_reservations(
    tmp_path: Path,
) -> None:
    from vinctor_service.idempotency_lifecycle import IdempotencyLifecycleController

    database = tmp_path / "restart.sqlite3"
    first = IdempotencyLifecycleController.sqlite(database, env=_configured_env(database))
    first.reserve_nonce(version="primary")
    before = first.status("primary").reserved_encryption_slots
    first.close()
    second = IdempotencyLifecycleController.sqlite(database, env=_configured_env(database))
    assert second.status("primary").reserved_encryption_slots == before

def test_lifecycle_cli_requires_explicit_old_version_and_rejects_active_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    missing, active = exercise_old_version_cli_rejections(
        tmp_path / "cli.sqlite3",
        monkeypatch,
    )
    assert missing != 0
    assert active != 0

def test_lifecycle_cli_output_and_errors_redact_keyring_and_dsn(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = exercise_cli_redaction(tmp_path / "redaction.sqlite3", monkeypatch)
    assert result.success == 0
    assert result.failure != 0
    assert "idempotency_unavailable" in result.failure_stderr
    assert "connection refused" not in result.rendered.lower()
    assert "psycopg" not in result.rendered.lower()
    assert all(secret not in result.rendered for secret in result.secrets)
