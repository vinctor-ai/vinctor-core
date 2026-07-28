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
from vinctor_service.idempotency_models import (
    CacheableTerminalOutcome,
    CryptoReservation,
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
) -> CacheableTerminalOutcome:
    callbacks.append(generation)
    connection.execute(
        "INSERT INTO reservation_consumption_marker(generation) VALUES (?)",
        (generation,),
    )
    writer.write(audit_event(f"evt_reservation_{generation}"))
    return outcome(f'{{"generation":"{generation}"}}'.encode())


def _insert_result(connection, owner, reservation: CryptoReservation) -> None:
    connection.execute(
        "INSERT INTO idempotency_results "
        "(workspace_id, principal, operation, key_hash, request_fingerprint, "
        "format_version, status_code, cipher_key_version, response_nonce, "
        "response_ciphertext, created_at_epoch, expires_at_epoch) "
        "VALUES (?, ?, ?, ?, ?, 1, 201, ?, ?, ?, 1, 4102444800)",
        (
            *owner.reservation_owner_identity,
            reservation.version,
            reservation.nonce,
            b"x" * 16,
        ),
    )
    connection.commit()


def test_sqlite_consumed_ledger_without_result_is_denied_before_effects(
    tmp_path: Path,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "consumed-no-result.sqlite")
    owner = invocation()
    try:
        reservation = store.reserve_nonce(owner, now_epoch=100)
        connection.execute(
            "UPDATE idempotency_cipher_nonces SET claimed_at_epoch = 101 "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reservation.version, reservation.nonce),
        )
        connection.commit()
        before = connection.execute("SELECT * FROM idempotency_cipher_nonces").fetchall()

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(
                owner,
                reservation,
                lambda: pytest.fail("consumed reservation entered callback"),
            )

        assert connection.execute("SELECT * FROM idempotency_cipher_nonces").fetchall() == before
        assert count_rows(connection, "idempotency_results") == 0
        assert count_rows(connection, "audit_events") == 0
    finally:
        connection.close()


@pytest.mark.parametrize("result_owner", ("same", "cross"))
def test_sqlite_unconsumed_reservation_with_existing_nonce_result_is_denied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    result_owner: str,
) -> None:
    connection, store, _executor = configured_executor(
        tmp_path / f"unconsumed-result-{result_owner}.sqlite"
    )
    owner = invocation()
    other = replace(
        owner,
        principal="agent:b",
        key_hash=b"b" * 32,
        request_fingerprint=b"B" * 32,
    )
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    writer = SQLiteAuditWriter(connection)
    real_encrypt = sqlite_store_module.encrypt_response

    def counted_encrypt(**kwargs):
        encryptions.append(kwargs["reservation"].nonce)
        return real_encrypt(**kwargs)

    monkeypatch.setattr(sqlite_store_module, "encrypt_response", counted_encrypt)
    try:
        _create_marker(connection)
        reservation = store.reserve_nonce(owner, now_epoch=100)
        _insert_result(connection, owner if result_owner == "same" else other, reservation)
        before = connection.execute("SELECT * FROM idempotency_results").fetchall()

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(
                owner,
                reservation,
                lambda: _mutation(connection, writer, callbacks, "forbidden"),
            )

        assert callbacks == []
        assert encryptions == []
        assert count_rows(connection, "reservation_consumption_marker") == 0
        assert count_rows(connection, "audit_events") == 0
        assert connection.execute("SELECT * FROM idempotency_results").fetchall() == before
    finally:
        connection.close()


@pytest.mark.parametrize("mismatch", ("owner", "nonce"))
def test_sqlite_consumed_result_mismatch_is_denied_before_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mismatch: str,
) -> None:
    connection, store, _executor = configured_executor(
        tmp_path / f"consumed-result-{mismatch}.sqlite"
    )
    owner = invocation()
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    writer = SQLiteAuditWriter(connection)
    real_encrypt = sqlite_store_module.encrypt_response

    def counted_encrypt(**kwargs):
        encryptions.append(kwargs["reservation"].nonce)
        return real_encrypt(**kwargs)

    monkeypatch.setattr(sqlite_store_module, "encrypt_response", counted_encrypt)
    try:
        _create_marker(connection)
        reservation = store.reserve_nonce(owner, now_epoch=100)
        store.complete(
            owner,
            reservation,
            lambda: _mutation(connection, writer, callbacks, "first"),
        )
        if mismatch == "owner":
            connection.execute(
                "UPDATE idempotency_results SET principal = ?, key_hash = ?",
                ("agent:b", b"b" * 32),
            )
        else:
            connection.execute(
                "UPDATE idempotency_results SET response_nonce = ?",
                (b"x" * 12,),
            )
        connection.commit()
        before = (
            connection.execute("SELECT * FROM idempotency_results").fetchall(),
            count_rows(connection, "reservation_consumption_marker"),
            count_rows(connection, "audit_events"),
            tuple(callbacks),
            tuple(encryptions),
        )

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(
                owner,
                reservation,
                lambda: _mutation(connection, writer, callbacks, "forbidden"),
            )

        assert (
            connection.execute("SELECT * FROM idempotency_results").fetchall(),
            count_rows(connection, "reservation_consumption_marker"),
            count_rows(connection, "audit_events"),
            tuple(callbacks),
            tuple(encryptions),
        ) == before
    finally:
        connection.close()
