from __future__ import annotations

import base64
from dataclasses import replace
from pathlib import Path

import pytest
from idempotency_sqlite_fixtures import invocation, outcome

from vinctor_service import idempotency_sqlite_completion
from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_lifecycle import (
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
    IdempotencyLifecycleController,
    IdempotencyLifecycleRejected,
    IdempotencyLifecycleUnavailable,
    IdempotencyRetirementRequest,
)
from vinctor_service.idempotency_models import CacheableTerminalOutcome
from vinctor_service.idempotency_sqlite import (
    SQLiteIdempotencyStore,
    SQLiteIdempotentMutationExecutor,
)
from vinctor_service.sqlite import init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


def _environment(database: Path, *, include_old: bool = True) -> dict[str, str]:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    primary = base64.b64encode(b"p" * 32).decode("ascii")
    entries = f'"primary":"{primary}"'
    if include_old:
        entries = f'"old":"{old}",{entries}'
    return {
        "VINCTOR_DB": str(database),
        "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f"{{{entries}}}",
        "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
    }


def _old_active_keyring():
    old = base64.b64encode(b"o" * 32).decode("ascii")
    primary = base64.b64encode(b"p" * 32).decode("ascii")
    return load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (
                f'{{"old":"{old}","primary":"{primary}"}}'
            ),
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "old",
        }
    )


def _seed_authentic_expired_old_result(
    database: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    key_hash: bytes = b"k" * 32,
) -> None:
    connection = connect_sqlite(database)
    try:
        init_sqlite_schema(connection)
        store = SQLiteIdempotencyStore(connection, keyring=_old_active_keyring())
        request = invocation(key_hash=key_hash)
        reservation = store.reserve_nonce(request, now_epoch=100)
        with monkeypatch.context() as patch:
            patch.setattr(
                idempotency_sqlite_completion,
                "sqlite_database_epoch",
                lambda _connection: 100,
            )
            store.complete(
                request,
                reservation,
                lambda: replace(outcome(), replay_not_after_epoch=101),
            )
    finally:
        connection.close()


def _advance_removal_window(database: Path) -> None:
    connection = connect_sqlite(database)
    try:
        row = connection.execute("SELECT CAST(strftime('%s', 'now') AS INTEGER)").fetchone()
        assert row is not None
        connection.execute(
            "UPDATE idempotency_cipher_key_versions "
            "SET first_seen_epoch = ?, write_disabled_epoch = ?, "
            "drain_completed_epoch = ? WHERE version_label = 'old'",
            (
                int(row[0]) - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS - 2,
                int(row[0]) - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS - 1,
                int(row[0]) - IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
            ),
        )
        connection.commit()
    finally:
        connection.close()


def _prepare_retirement(
    database: Path,
) -> tuple[IdempotencyLifecycleController, IdempotencyRetirementRequest]:
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_environment(database),
    )
    controller.write_disable(version="old", reason="rotation")
    controller.complete_drain(version="old", confirm_no_active_writers=True)
    _advance_removal_window(database)
    return controller, IdempotencyRetirementRequest(
        version="old",
        confirm_removal_window=True,
    )


def test_sqlite_retirement_authenticates_and_removes_expired_results_before_tombstone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an authentic expired result protected by the retiring key.
    database = tmp_path / "retire-expired.sqlite3"
    _seed_authentic_expired_old_result(database, monkeypatch)
    controller, request = _prepare_retirement(database)
    try:
        # When the lifecycle operation retires the old version.
        controller.retire(request)

        # Then cleanup and the tombstone commit together.
        connection = connect_sqlite(database)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 0
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is not None
    finally:
        controller.close()

    new_keyring = load_idempotency_keyring(_environment(database, include_old=False))
    connection = connect_sqlite(database)
    calls = 0
    try:
        store = SQLiteIdempotencyStore(connection, keyring=new_keyring)
        executor = SQLiteIdempotentMutationExecutor(store)

        def mutation() -> CacheableTerminalOutcome:
            nonlocal calls
            calls += 1
            return outcome(b'{"fresh":true}')

        response = executor.execute(invocation(), mutation)
        assert response.body == b'{"fresh":true}'
        assert calls == 1
    finally:
        connection.close()


def test_sqlite_retirement_preserves_corrupt_expired_result_and_tombstone(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an expired result whose authenticated ciphertext has been corrupted.
    database = tmp_path / "retire-corrupt.sqlite3"
    _seed_authentic_expired_old_result(database, monkeypatch)
    connection = connect_sqlite(database)
    try:
        connection.execute(
            "UPDATE idempotency_results SET response_ciphertext = ?",
            (b"x" * 16,),
        )
        connection.commit()
    finally:
        connection.close()
    controller, request = _prepare_retirement(database)
    try:
        # When retirement attempts to drain stored results.
        with pytest.raises(IdempotencyLifecycleUnavailable):
            controller.retire(request)

        # Then neither the row nor the retirement tombstone is changed.
        connection = connect_sqlite(database)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 1
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is None
    finally:
        controller.close()


def test_sqlite_retirement_rejects_corrupt_unexpired_result_without_decryption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a corrupt row that is still materially unexpired.
    database = tmp_path / "retire-corrupt-unexpired.sqlite3"
    _seed_authentic_expired_old_result(database, monkeypatch)
    connection = connect_sqlite(database)
    try:
        now_row = connection.execute(
            "SELECT CAST(strftime('%s', 'now') AS INTEGER)"
        ).fetchone()
        assert now_row is not None
        connection.execute(
            "UPDATE idempotency_results "
            "SET response_ciphertext = ?, expires_at_epoch = ?",
            (b"x" * 16, int(now_row[0]) + 3_600),
        )
        connection.commit()
    finally:
        connection.close()
    controller, request = _prepare_retirement(database)
    try:
        # When retirement checks the old key version.
        with pytest.raises(
            IdempotencyLifecycleRejected,
            match="unexpired_results_remain",
        ):
            controller.retire(request)

        # Then it preserves the opaque unexpired row and the retirement state.
        connection = connect_sqlite(database)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 1
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is None
    finally:
        controller.close()


def test_sqlite_retirement_rolls_back_prior_expired_delete_on_later_corruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an authentic expired row followed by a corrupt expired row.
    database = tmp_path / "retire-mixed.sqlite3"
    _seed_authentic_expired_old_result(database, monkeypatch)
    _seed_authentic_expired_old_result(
        database,
        monkeypatch,
        key_hash=b"z" * 32,
    )
    connection = connect_sqlite(database)
    try:
        connection.execute(
            "UPDATE idempotency_results SET response_ciphertext = ? WHERE key_hash = ?",
            (b"x" * 16, b"z" * 32),
        )
        connection.commit()
    finally:
        connection.close()
    controller, request = _prepare_retirement(database)
    try:
        # When cleanup reaches the corrupt expired row after the authentic row.
        with pytest.raises(IdempotencyLifecycleUnavailable):
            controller.retire(request)

        # Then the transaction restores the earlier deletion and does not retire.
        connection = connect_sqlite(database)
        try:
            row = connection.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
            assert row is not None and int(row[0]) == 2
        finally:
            connection.close()
        assert controller.status("old").retired_epoch is None
    finally:
        controller.close()
