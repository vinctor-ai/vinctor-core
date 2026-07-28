from __future__ import annotations

from pathlib import Path

import pytest
from idempotency_lifecycle_writer_attestation_fixtures import (
    _PRIMARY,
    _RETIRING,
    _forced_carrier,
    _keyring,
    _lifecycle_env,
)

from vinctor_service import idempotency_lifecycle_lock
from vinctor_service.idempotency_keyring import (
    IdempotencyKeyringConfigError,
)
from vinctor_service.idempotency_lifecycle import (
    IdempotencyLifecycleActiveWriters,
    IdempotencyLifecycleController,
    IdempotencyLifecycleUnavailable,
)
from vinctor_service.idempotency_lifecycle_lock import SQLiteWriterAttestation
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite


def test_sqlite_carrier_collision_fails_closed_without_aliasing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        idempotency_lifecycle_lock,
        "_version_lock_carrier",
        _forced_carrier,
        raising=False,
    )
    first = SQLiteWriterAttestation(tmp_path / "collision.sqlite3", _RETIRING)
    second = SQLiteWriterAttestation(tmp_path / "collision.sqlite3", _PRIMARY)
    first.register()
    try:
        with pytest.raises(IdempotencyLifecycleUnavailable):
            second.register()
    finally:
        first.close()
        second.close()

def test_exclusive_target_prevents_constructor_registry_side_effect(
    tmp_path: Path,
) -> None:
    database = tmp_path / "constructor.sqlite3"
    initial_connection = connect_sqlite(database, check_same_thread=False)
    initial_service = SQLiteV1Service(initial_connection)
    initial_service.close()
    initial_connection.close()

    guard = SQLiteWriterAttestation(database, _RETIRING)
    candidate_connection = connect_sqlite(database, check_same_thread=False)
    with guard.exclusive_guard(), pytest.raises(IdempotencyLifecycleActiveWriters):
        SQLiteV1Service(
            candidate_connection,
            idempotency_keyring=_keyring(_RETIRING),
        )
    row = candidate_connection.execute(
        "SELECT COUNT(*) FROM idempotency_cipher_key_versions WHERE version_label = ?",
        (_RETIRING,),
    ).fetchone()
    candidate_connection.close()
    assert row == (0,)

def test_late_disabled_target_constructor_is_never_published(
    tmp_path: Path,
) -> None:
    database = tmp_path / "late.sqlite3"
    with IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    ) as controller:
        controller.write_disable(version=_RETIRING, reason="rotation")
        controller.complete_drain(
            version=_RETIRING,
            confirm_no_active_writers=True,
        )
    connection = connect_sqlite(database, check_same_thread=False)
    try:
        with pytest.raises(IdempotencyKeyringConfigError):
            SQLiteV1Service(
                connection,
                idempotency_keyring=_keyring(_RETIRING),
            )
    finally:
        connection.close()
