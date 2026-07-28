from __future__ import annotations

import base64
import threading
import time

import pytest
from idempotency_postgres_faults import inject_commit_ack_loss

from vinctor_service.idempotency_keyring import (
    IdempotencyKeyring,
    IdempotencyKeyringConfigError,
    load_idempotency_keyring,
)
from vinctor_service.idempotency_lifecycle import (
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
    IdempotencyLifecycleActiveWriters,
    IdempotencyLifecycleController,
    IdempotencyRetirementRequest,
)
from vinctor_service.idempotency_lifecycle_postgres_lock import (
    PostgresWriterAttestation,
)
from vinctor_service.idempotency_models import AmbiguousCommitError
from vinctor_service.postgres import PostgresV1Service, connect_postgres
from vinctor_service.service_config import load_service_runtime_config


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


def _controller(dsn: str) -> IdempotencyLifecycleController:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    replacement = base64.b64encode(b"r" * 32).decode("ascii")
    config = load_service_runtime_config(
        env={
            "VINCTOR_STORAGE_BACKEND": "postgres",
            "VINCTOR_POSTGRES_DSN": dsn,
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (
                f'{{"old":"{old}","replacement":"{replacement}"}}'
            ),
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "replacement",
        }
    )
    return IdempotencyLifecycleController.from_config(config)


def _age_old_drain(dsn: str) -> None:
    connection = connect_postgres(dsn)
    try:
        with connection.transaction():
            connection.execute(
                "UPDATE idempotency_cipher_key_versions "
                "SET first_seen_epoch = "
                "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s - 2, "
                "write_disabled_epoch = "
                "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s - 1, "
                "drain_completed_epoch = "
                "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s "
                "WHERE version_label = %s",
                (
                    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                    "old",
                ),
            )
    finally:
        connection.close()


def test_real_postgres_service_blocks_drain_and_retire_until_idempotent_close(
    requires_postgres: str,
) -> None:
    # Given an actual old-key PostgreSQL service holding its writer session open.
    connection = connect_postgres(requires_postgres)
    service = PostgresV1Service(connection, idempotency_keyring=_keyring("old"))
    controller = _controller(requires_postgres)
    controller.write_disable(version="old", reason="rotation")

    try:
        # When exclusive drain is attempted before and after service close.
        with pytest.raises(IdempotencyLifecycleActiveWriters):
            controller.complete_drain(
                version="old",
                confirm_no_active_writers=True,
            )
        _age_old_drain(requires_postgres)
        with pytest.raises(IdempotencyLifecycleActiveWriters):
            controller.retire(
                IdempotencyRetirementRequest(
                    version="old",
                    confirm_removal_window=True,
                )
            )
        service.close()
        service.close()
        connection.close()
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )
        controller.retire(
            IdempotencyRetirementRequest(
                version="old",
                confirm_removal_window=True,
            )
        )

        # Then only post-close operations can complete the target lifecycle.
        assert controller.status("old").retired_epoch is not None
    finally:
        close_service = getattr(service, "close", None)
        if callable(close_service):
            close_service()
        connection.close()
        controller.close()


def test_real_postgres_replacement_service_does_not_block_old_lifecycle(
    requires_postgres: str,
) -> None:
    connection = connect_postgres(requires_postgres)
    service = PostgresV1Service(
        connection,
        idempotency_keyring=_keyring("replacement"),
    )
    controller = _controller(requires_postgres)
    try:
        controller.write_disable(version="old", reason="rotation")
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )
        _age_old_drain(requires_postgres)
        controller.retire(
            IdempotencyRetirementRequest(
                version="old",
                confirm_removal_window=True,
            )
        )
        assert controller.status("old").retired_epoch is not None
    finally:
        service.close()
        connection.close()
        controller.close()


def test_real_postgres_late_old_constructor_revalidates_after_target_guard(
    requires_postgres: str,
) -> None:
    controller = _controller(requires_postgres)
    guard_connection = connect_postgres(requires_postgres)
    candidate_connection = connect_postgres(requires_postgres)
    observer = connect_postgres(requires_postgres)
    guard = PostgresWriterAttestation(guard_connection, "old")
    services: list[PostgresV1Service] = []
    rejections: list[IdempotencyKeyringConfigError] = []

    def construct_candidate() -> None:
        try:
            services.append(
                PostgresV1Service(
                    candidate_connection,
                    idempotency_keyring=_keyring("old"),
                )
            )
        except IdempotencyKeyringConfigError as exc:
            rejections.append(exc)

    with candidate_connection.transaction():
        row = candidate_connection.execute("SELECT pg_backend_pid()").fetchone()
    assert row is not None
    backend_pid = int(row[0])

    try:
        with guard.exclusive_guard():
            thread = threading.Thread(target=construct_candidate)
            thread.start()
            deadline = time.monotonic() + 5
            waiting = False
            while time.monotonic() < deadline:
                with observer.transaction():
                    waiting_row = observer.execute(
                        "SELECT EXISTS("
                        "SELECT 1 FROM pg_locks "
                        "WHERE pid = %s AND locktype = 'advisory' AND NOT granted"
                        ")",
                        (backend_pid,),
                    ).fetchone()
                waiting = waiting_row == (True,)
                if waiting:
                    break
                time.sleep(0.01)
            assert waiting
            controller.write_disable(version="old", reason="rotation")
        thread.join(timeout=5)
        assert thread.is_alive() is False
        assert services == []
        assert len(rejections) == 1
    finally:
        for service in services:
            service.close()
        candidate_connection.close()
        observer.close()
        guard_connection.close()
        controller.close()


def test_postgres_ambiguity_recovery_restores_writer_lock_before_publish(
    requires_postgres: str,
) -> None:
    # Given an actual writer whose physical advisory-lock session loses commit ACK.
    connection = connect_postgres(requires_postgres)
    service = PostgresV1Service(connection, idempotency_keyring=_keyring("old"))
    old_generation = connection.generation
    inject_commit_ack_loss(
        connection,
        transaction_boundary=1,
        commit_happened=True,
    )
    with pytest.raises(AmbiguousCommitError), connection.transaction():
        connection.execute("SELECT 1")
    assert connection.is_quarantined is True

    # When the same service graph publishes a fresh physical generation.
    assert connection.execute("SELECT 1").fetchone() == (1,)
    assert connection.generation > old_generation
    controller = _controller(requires_postgres)
    controller.write_disable(version="old", reason="rotation")

    try:
        # Then the recovered real writer still blocks exclusive drain.
        with pytest.raises(IdempotencyLifecycleActiveWriters):
            controller.complete_drain(
                version="old",
                confirm_no_active_writers=True,
            )
        service.close()
        connection.close()
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )
    finally:
        close_service = getattr(service, "close", None)
        if callable(close_service):
            close_service()
        connection.close()
        controller.close()
