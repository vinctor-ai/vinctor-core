from __future__ import annotations

import base64
import fcntl
from pathlib import Path

import pytest

from vinctor_service.idempotency_keyring import IdempotencyKeyring, load_idempotency_keyring
from vinctor_service.idempotency_lifecycle import (
    IdempotencyLifecycleActiveWriters,
    IdempotencyLifecycleController,
    IdempotencyLifecycleUnavailable,
)
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_pool import SQLiteServicePool
from vinctor_service.sqlite_txn import connect_sqlite


def _keyring(active_version: str) -> IdempotencyKeyring:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    replacement = base64.b64encode(b"r" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (
                f'{{"old":"{old}","replacement":"{replacement}"}}'
            ),
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": active_version,
        }
    )
    assert keyring is not None
    return keyring


def _lifecycle_env(database: Path) -> dict[str, str]:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    replacement = base64.b64encode(b"r" * 32).decode("ascii")
    return {
        "VINCTOR_DB": str(database),
        "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (f'{{"old":"{old}","replacement":"{replacement}"}}'),
        "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "replacement",
    }


def test_real_sqlite_service_owns_writer_lock_until_idempotent_close(
    tmp_path: Path,
) -> None:
    # Given a real old-key service without manual lifecycle registration.
    database = tmp_path / "real-service.sqlite3"
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=_keyring("old"))
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    )
    controller.write_disable(version="old", reason="rotation")

    try:
        # When drain is attempted during the service lifetime.
        with pytest.raises(IdempotencyLifecycleActiveWriters):
            controller.complete_drain(
                version="old",
                confirm_no_active_writers=True,
            )
        service.close()
        service.close()
        connection.close()
        controller.close()

        # Then a restarted lifecycle authority can commit drain after release.
        with IdempotencyLifecycleController.sqlite(
            database,
            env=_lifecycle_env(database),
        ) as restarted:
            restarted.complete_drain(
                version="old",
                confirm_no_active_writers=True,
            )
            assert restarted.status("old").drain_completed_epoch is not None
    finally:
        close_service = getattr(service, "close", None)
        if callable(close_service):
            close_service()
        connection.close()
        controller.close()


def test_sqlite_service_attestation_acquisition_failure_releases_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an OS failure immediately after a shared file lock is acquired.
    from vinctor_service import idempotency_lifecycle_lock

    database = tmp_path / "construction-failure.sqlite3"
    connection = connect_sqlite(database, check_same_thread=False)
    original_flock = idempotency_lifecycle_lock.fcntl.flock

    def fail_after_shared_lock(file_descriptor: int, operation: int) -> None:
        original_flock(file_descriptor, operation)
        if operation & fcntl.LOCK_SH:
            raise OSError("writer attestation acquisition failed")

    monkeypatch.setattr(
        idempotency_lifecycle_lock.fcntl,
        "flock",
        fail_after_shared_lock,
    )
    try:
        # When construction cannot finish writer registration.
        with pytest.raises(IdempotencyLifecycleUnavailable):
            SQLiteV1Service(connection, idempotency_keyring=_keyring("old"))
    finally:
        monkeypatch.setattr(
            idempotency_lifecycle_lock.fcntl,
            "flock",
            original_flock,
        )
        connection.close()

    # Then no stale shared lock can block a subsequent exclusive drain.
    with IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    ) as controller:
        controller.write_disable(version="old", reason="rotation")
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )


def test_replacement_sqlite_pool_generations_do_not_block_old_drain(
    tmp_path: Path,
) -> None:
    # Given two real keyed pooled services on the lifecycle database.
    database = tmp_path / "pool-generations.sqlite3"
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(
        connection,
        idempotency_keyring=_keyring("replacement"),
    )
    pool = SQLiteServicePool(
        database,
        primary_connection=connection,
        primary_service=service,
        primary_key_repository=SQLiteLocalKeyRepository(connection),
        size=2,
    )
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    )
    controller.write_disable(version="old", reason="rotation")

    try:
        # When old drain runs while only replacement-version generations serve.
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )
        with pool.request_scope():
            old_generation = pool.current_context.generation
            assert pool.quarantine_current_context(old_generation) is True
        replacement_generation = max(context.generation for context in pool._contexts)

        # Then replacement publication remains version-separated and idempotent.
        assert replacement_generation > old_generation
        assert pool.capacity == 2
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )
        pool.close()
        pool.close()
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )
    finally:
        pool.close()
        controller.close()


def test_unkeyed_sqlite_service_does_not_acquire_writer_attestation(
    tmp_path: Path,
) -> None:
    # Given a default-off unkeyed service on the lifecycle database.
    database = tmp_path / "unkeyed.sqlite3"
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection)
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    )
    controller.write_disable(version="old", reason="rotation")

    try:
        # When drain is attempted while only the unkeyed service is open.
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )

        # Then default-off behavior remains fail-open and close is idempotent.
        assert controller.status("old").drain_completed_epoch is not None
        service.close()
        service.close()
    finally:
        close_service = getattr(service, "close", None)
        if callable(close_service):
            close_service()
        connection.close()
        controller.close()
