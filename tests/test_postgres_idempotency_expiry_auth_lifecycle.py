from __future__ import annotations

import base64
from dataclasses import replace

import pytest
from idempotency_postgres_fixtures import invocation, outcome

from vinctor_service import idempotency_postgres_completion
from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_lifecycle import (
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
    IdempotencyLifecycleController,
    IdempotencyLifecycleRejected,
    IdempotencyLifecycleUnavailable,
    IdempotencyRetirementRequest,
)
from vinctor_service.idempotency_postgres import (
    PostgresIdempotencyStore,
    PostgresIdempotentMutationExecutor,
)
from vinctor_service.postgres import connect_postgres, init_postgres_schema
from vinctor_service.service_config import load_service_runtime_config


def _encoded_keys() -> tuple[str, str]:
    return (
        base64.b64encode(b"o" * 32).decode("ascii"),
        base64.b64encode(b"p" * 32).decode("ascii"),
    )


def _keyring(*, active: str, include_old: bool = True):
    old, primary = _encoded_keys()
    entries = f'"primary":"{primary}"'
    if include_old:
        entries = f'"old":"{old}",{entries}'
    return load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f"{{{entries}}}",
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": active,
        }
    )


def _controller(dsn: str) -> IdempotencyLifecycleController:
    old, primary = _encoded_keys()
    return IdempotencyLifecycleController.from_config(
        load_service_runtime_config(
            env={
                "VINCTOR_STORAGE_BACKEND": "postgres",
                "VINCTOR_POSTGRES_DSN": dsn,
                "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (
                    f'{{"old":"{old}","primary":"{primary}"}}'
                ),
                "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
            }
        )
    )


def _seed_expired_result(
    dsn: str,
    monkeypatch: pytest.MonkeyPatch,
    *,
    key_hash: bytes = b"k" * 32,
) -> None:
    connection = connect_postgres(dsn)
    try:
        init_postgres_schema(connection)
        store = PostgresIdempotencyStore(connection, keyring=_keyring(active="old"))
        request = invocation(key_hash=key_hash)
        reservation = store.reserve_nonce(request, now_epoch=100)
        with monkeypatch.context() as patch:
            patch.setattr(
                idempotency_postgres_completion,
                "postgres_database_epoch",
                lambda _connection: 100,
            )
            store.complete(
                request,
                reservation,
                lambda: replace(outcome(), replay_not_after_epoch=101),
            )
    finally:
        connection.close()


def _prepare_retirement(
    dsn: str,
) -> tuple[IdempotencyLifecycleController, IdempotencyRetirementRequest]:
    controller = _controller(dsn)
    controller.write_disable(version="old", reason="rotation")
    controller.complete_drain(version="old", confirm_no_active_writers=True)
    maintenance = connect_postgres(dsn)
    try:
        with maintenance.transaction():
            maintenance.execute(
                "UPDATE idempotency_cipher_key_versions "
                "SET first_seen_epoch = "
                "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s - 2, "
                "write_disabled_epoch = "
                "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s - 1, "
                "drain_completed_epoch = "
                "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s "
                "WHERE version_label = 'old'",
                (
                    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                ),
            )
    finally:
        maintenance.close()
    return controller, IdempotencyRetirementRequest(
        version="old",
        confirm_removal_window=True,
    )


def test_postgres_retirement_authenticates_and_removes_expired_result(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an authentic expired result protected by the retiring key.
    _seed_expired_result(requires_postgres, monkeypatch)
    controller, request = _prepare_retirement(requires_postgres)
    try:
        # When retirement succeeds.
        controller.retire(request)

        # Then the result is removed before the tombstone commits.
        connection = connect_postgres(requires_postgres)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 0
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is not None
    finally:
        controller.close()

    connection = connect_postgres(requires_postgres)
    try:
        store = PostgresIdempotencyStore(
            connection,
            keyring=_keyring(active="primary", include_old=False),
        )
        executor = PostgresIdempotentMutationExecutor(store)
        assert executor.execute(invocation(), lambda: outcome(b'{"fresh":true}')).body == (
            b'{"fresh":true}'
        )
    finally:
        connection.close()


def test_postgres_retirement_preserves_corrupt_expired_result(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a corrupt expired result under the retiring key.
    _seed_expired_result(requires_postgres, monkeypatch)
    connection = connect_postgres(requires_postgres)
    try:
        with connection.transaction():
            connection.execute(
                "UPDATE idempotency_results SET response_ciphertext = %s",
                (b"x" * 16,),
            )
    finally:
        connection.close()
    controller, request = _prepare_retirement(requires_postgres)
    try:
        # When retirement authenticates the result.
        with pytest.raises(IdempotencyLifecycleUnavailable):
            controller.retire(request)

        # Then the corrupt row remains and no tombstone is written.
        connection = connect_postgres(requires_postgres)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 1
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is None
    finally:
        controller.close()


def test_postgres_retirement_rejects_corrupt_unexpired_result_without_decryption(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a corrupt row that is still materially unexpired.
    _seed_expired_result(requires_postgres, monkeypatch)
    connection = connect_postgres(requires_postgres)
    try:
        with connection.transaction():
            connection.execute(
                "UPDATE idempotency_results "
                "SET response_ciphertext = %s, "
                "expires_at_epoch = FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT + 3600",
                (b"x" * 16,),
            )
    finally:
        connection.close()
    controller, request = _prepare_retirement(requires_postgres)
    try:
        # When retirement checks the old key version.
        with pytest.raises(
            IdempotencyLifecycleRejected,
            match="unexpired_results_remain",
        ):
            controller.retire(request)

        # Then it preserves the opaque unexpired row and the retirement state.
        connection = connect_postgres(requires_postgres)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 1
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is None
    finally:
        controller.close()


def test_postgres_retirement_rolls_back_prior_expired_delete_on_later_corruption(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an authentic expired row followed by a corrupt expired row.
    _seed_expired_result(requires_postgres, monkeypatch)
    _seed_expired_result(
        requires_postgres,
        monkeypatch,
        key_hash=b"z" * 32,
    )
    connection = connect_postgres(requires_postgres)
    try:
        with connection.transaction():
            connection.execute(
                "UPDATE idempotency_results SET response_ciphertext = %s "
                "WHERE key_hash = %s",
                (b"x" * 16, b"z" * 32),
            )
    finally:
        connection.close()
    controller, request = _prepare_retirement(requires_postgres)
    try:
        # When cleanup reaches the corrupt expired row after the authentic row.
        with pytest.raises(IdempotencyLifecycleUnavailable):
            controller.retire(request)

        # Then the transaction restores the earlier deletion and does not retire.
        connection = connect_postgres(requires_postgres)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 2
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is None
    finally:
        controller.close()
