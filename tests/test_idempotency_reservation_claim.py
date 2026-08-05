from __future__ import annotations

import base64
import threading
from pathlib import Path

import pytest
from idempotency_sqlite_fixtures import configured_executor, count_rows, invocation, outcome

from vinctor_service import idempotency_sqlite as sqlite_store_module
from vinctor_service import idempotency_sqlite_completion as sqlite_completion
from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import (
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore
from vinctor_service.sqlite import init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


def test_sqlite_result_insert_rollback_keeps_claim_and_rejects_same_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "rollback-claim.sqlite")
    owner = invocation()
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    real_encrypt = sqlite_store_module.encrypt_response

    def counted_encrypt(
        *,
        key: IdempotencyKeyVersion,
        reservation: CryptoReservation,
        plaintext: bytes,
        aad: bytes,
    ) -> EncryptedResponseEnvelope:
        encryptions.append(reservation.nonce)
        return real_encrypt(
            key=key,
            reservation=reservation,
            plaintext=plaintext,
            aad=aad,
        )

    def mutate():
        callbacks.append("called")
        connection.execute("INSERT INTO claim_business_state(value) VALUES ('written')")
        return outcome()

    monkeypatch.setattr(sqlite_store_module, "encrypt_response", counted_encrypt)
    try:
        connection.execute("CREATE TABLE claim_business_state(value TEXT NOT NULL)")
        connection.execute(
            "CREATE TRIGGER fail_idempotency_result "
            "BEFORE INSERT ON idempotency_results BEGIN "
            "SELECT RAISE(ABORT, 'forced result insert failure'); END"
        )
        connection.commit()
        reservation = store.reserve_nonce(owner, now_epoch=100)

        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            store.complete(owner, reservation, mutate)
        assert captured.value.__cause__ is None

        claimed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        ).fetchone()
        connection.execute("DROP TRIGGER fail_idempotency_result")
        connection.commit()
        before_retry = (
            tuple(callbacks),
            tuple(encryptions),
            count_rows(connection, "claim_business_state"),
            count_rows(connection, "audit_events"),
            count_rows(connection, "idempotency_results"),
        )

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(owner, reservation, mutate)

        assert claimed is not None and claimed[0] is not None
        assert (
            (
                tuple(callbacks),
                tuple(encryptions),
                count_rows(connection, "claim_business_state"),
                count_rows(connection, "audit_events"),
                count_rows(connection, "idempotency_results"),
            )
            == before_retry
            == ((("called",)), (reservation.nonce,), 0, 0, 0)
        )

        fresh = store.reserve_nonce(owner, now_epoch=101)
        response = store.complete(owner, fresh, mutate)
        assert response.body == b'{"ok":true}'
        assert callbacks == ["called", "called"]
        assert encryptions == [reservation.nonce, fresh.nonce]
    finally:
        connection.close()


def test_sqlite_crash_after_claim_before_phase_two_burns_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "crash-after-claim.sqlite")
    owner = invocation()
    reservation = store.reserve_nonce(owner, now_epoch=100)
    real_complete = sqlite_completion.complete_sqlite_result
    mutation_calls: list[str] = []
    monkeypatch.setattr(
        sqlite_completion,
        "complete_sqlite_result",
        pytest.importorskip("unittest.mock").Mock(side_effect=SystemExit("forced crash")),
    )
    try:
        with pytest.raises(SystemExit, match="forced crash"):
            store.complete(owner, reservation, lambda: outcome())
        monkeypatch.setattr(sqlite_completion, "complete_sqlite_result", real_complete)
        claimed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        ).fetchone()

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(
                owner,
                reservation,
                lambda: mutation_calls.append("called") or outcome(),
            )

        assert claimed is not None and claimed[0] is not None
        assert mutation_calls == []
        assert count_rows(connection, "idempotency_results") == 0

        fresh = store.reserve_nonce(owner, now_epoch=101)
        assert store.complete(owner, fresh, lambda: outcome()).body == b'{"ok":true}'
        assert fresh.nonce != reservation.nonce
    finally:
        connection.close()


def test_sqlite_preclaim_schema_upgrade_burns_every_existing_reservation(
    tmp_path: Path,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "preclaim-upgrade.sqlite")
    owner = invocation()
    reservation = store.reserve_nonce(owner, now_epoch=100)
    try:
        connection.execute("ALTER TABLE idempotency_cipher_nonces DROP COLUMN claimed_at_epoch")
        connection.commit()
        init_sqlite_schema(connection)

        claimed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        ).fetchone()
        assert claimed is not None and claimed[0] is not None
    finally:
        connection.close()


def test_sqlite_concurrent_same_reservation_has_one_durable_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "concurrent-claim.sqlite"
    first_connection = connect_sqlite(database, check_same_thread=False)
    second_connection = connect_sqlite(database, check_same_thread=False)
    init_sqlite_schema(first_connection)
    key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    first_store = SQLiteIdempotencyStore(first_connection, keyring=keyring)
    second_store = SQLiteIdempotencyStore(second_connection, keyring=keyring)
    owner = invocation()
    reservation = first_store.reserve_nonce(owner, now_epoch=100)
    barrier = threading.Barrier(3)
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    failures: list[type[BaseException]] = []
    real_encrypt = sqlite_store_module.encrypt_response

    def counted_encrypt(
        *,
        key: IdempotencyKeyVersion,
        reservation: CryptoReservation,
        plaintext: bytes,
        aad: bytes,
    ) -> EncryptedResponseEnvelope:
        encryptions.append(reservation.nonce)
        return real_encrypt(
            key=key,
            reservation=reservation,
            plaintext=plaintext,
            aad=aad,
        )

    def run(store: SQLiteIdempotencyStore) -> None:
        barrier.wait()
        try:
            store.complete(
                owner,
                reservation,
                lambda: callbacks.append("called") or outcome(),
            )
        except IdempotencyWriteUnavailable as exc:
            failures.append(type(exc))

    monkeypatch.setattr(sqlite_store_module, "encrypt_response", counted_encrypt)
    try:
        first_connection.execute(
            "CREATE TRIGGER fail_concurrent_result "
            "BEFORE INSERT ON idempotency_results BEGIN "
            "SELECT RAISE(ABORT, 'forced concurrent result failure'); END"
        )
        first_connection.commit()
        threads = [
            threading.Thread(target=run, args=(first_store,)),
            threading.Thread(target=run, args=(second_store,)),
        ]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=10)

        assert all(not thread.is_alive() for thread in threads)
        assert callbacks == ["called"]
        assert encryptions == [reservation.nonce]
        assert sorted(failure.__name__ for failure in failures) == [
            "IdempotencyWriteUnavailable",
            "IdempotencyWriteUnavailable",
        ]
        claimed = first_connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        ).fetchone()
        assert claimed is not None and claimed[0] is not None
        assert count_rows(first_connection, "idempotency_results") == 0

        first_connection.execute("DROP TRIGGER fail_concurrent_result")
        first_connection.commit()
        fresh = first_store.reserve_nonce(owner, now_epoch=101)
        assert first_store.complete(owner, fresh, lambda: outcome()).body == b'{"ok":true}'
    finally:
        first_connection.close()
        second_connection.close()
