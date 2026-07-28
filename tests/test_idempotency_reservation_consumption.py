from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from idempotency_sqlite_fixtures import (
    audit_event,
    configured_executor,
    count_rows,
    invocation,
    outcome,
)

from vinctor_service import idempotency_sqlite as sqlite_store_module
from vinctor_service import idempotency_sqlite_completion as sqlite_completion
from vinctor_service.idempotency_models import (
    CacheableTerminalOutcome,
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyWriteUnavailable,
)
from vinctor_service.sqlite import SQLiteAuditWriter


def _create_marker(connection) -> None:
    connection.execute(
        "CREATE TABLE reservation_consumption_marker(generation TEXT NOT NULL UNIQUE)"
    )
    connection.commit()


def _mutation(
    connection,
    writer: SQLiteAuditWriter,
    callbacks: list[str],
    generation: str,
    *,
    replay_not_after_epoch: int | None = None,
) -> CacheableTerminalOutcome:
    callbacks.append(generation)
    connection.execute(
        "INSERT INTO reservation_consumption_marker(generation) VALUES (?)",
        (generation,),
    )
    writer.write(audit_event(f"evt_reservation_{generation}"))
    return replace(
        outcome(f'{{"generation":"{generation}"}}'.encode()),
        replay_not_after_epoch=replay_not_after_epoch,
    )


def test_sqlite_consumed_reservation_stays_burned_after_result_gc(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "gc-reuse.sqlite")
    owner = invocation()
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    now_epoch = 100
    writer = SQLiteAuditWriter(connection)
    real_encrypt = sqlite_store_module.encrypt_response
    monkeypatch.setattr(
        sqlite_completion,
        "sqlite_database_epoch",
        lambda _connection: now_epoch,
    )

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

    monkeypatch.setattr(sqlite_store_module, "encrypt_response", counted_encrypt)
    try:
        _create_marker(connection)
        old = store.reserve_nonce(owner, now_epoch=now_epoch)
        store.complete(
            owner,
            old,
            lambda: _mutation(
                connection,
                writer,
                callbacks,
                "first",
                replay_not_after_epoch=101,
            ),
        )
        now_epoch = 102
        assert store.gc_expired_results(limit=100) == 1
        before_old_retry = (
            tuple(callbacks),
            count_rows(connection, "reservation_consumption_marker"),
            count_rows(connection, "audit_events"),
            tuple(encryptions),
            count_rows(connection, "idempotency_results"),
        )

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(
                owner,
                old,
                lambda: _mutation(
                    connection,
                    writer,
                    callbacks,
                    "old-reuse",
                ),
            )

        assert (
            tuple(callbacks),
            count_rows(connection, "reservation_consumption_marker"),
            count_rows(connection, "audit_events"),
            tuple(encryptions),
            count_rows(connection, "idempotency_results"),
        ) == before_old_retry
        consumed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (old.version, old.nonce),
        ).fetchone()
        assert consumed is not None and consumed[0] is not None

        fresh = store.reserve_nonce(owner, now_epoch=now_epoch)
        response = store.complete(
            owner,
            fresh,
            lambda: _mutation(connection, writer, callbacks, "fresh"),
        )
        assert response.body == b'{"generation":"fresh"}'
        assert callbacks == ["first", "fresh"]
        assert encryptions == [old.nonce, fresh.nonce]
        assert old.nonce != fresh.nonce
        assert count_rows(connection, "idempotency_cipher_nonces") == 2
        assert count_rows(connection, "idempotency_results") == 1
    finally:
        connection.close()
