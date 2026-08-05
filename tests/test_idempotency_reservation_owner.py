from __future__ import annotations

import sqlite3
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
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyWriteUnavailable,
)
from vinctor_service.sqlite import SQLiteAuditWriter


@pytest.mark.parametrize(
    ("owner_field", "foreign_value"),
    (
        ("workspace_id", "ws-b"),
        ("principal", "agent:b"),
        ("operation", "grant.revoke.v1"),
        ("key_hash", b"b" * 32),
        ("request_fingerprint", b"B" * 32),
    ),
)
def test_sqlite_reservation_cannot_complete_a_different_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner_field: str,
    foreign_value: str | bytes,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "owner-reuse.sqlite")
    owner_a = invocation()
    owner_b = replace(owner_a, **{owner_field: foreign_value})
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    writer = SQLiteAuditWriter(connection)
    real_encrypt = sqlite_store_module.encrypt_response
    try:
        connection.execute("CREATE TABLE owner_business_marker(owner TEXT NOT NULL UNIQUE)")
        connection.commit()
        reservation = store.reserve_nonce(owner_a, now_epoch=100)
        ledger_before = connection.execute("SELECT * FROM idempotency_cipher_nonces").fetchall()

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

        def mutation(owner: str):
            def run():
                callbacks.append(owner)
                connection.execute(
                    "INSERT INTO owner_business_marker(owner) VALUES (?)",
                    (owner,),
                )
                writer.write(audit_event(f"evt_owner_{owner}"))
                return outcome(f'{{"owner":"{owner}"}}'.encode())

            return run

        denied_error: str | None = None
        denied_body: bytes | None = None
        try:
            denied_body = store.complete(owner_b, reservation, mutation("b")).body
        except IdempotencyWriteUnavailable as error:
            denied_error = str(error)
        after_denied = {
            "error": denied_error,
            "body": denied_body,
            "callbacks": tuple(callbacks),
            "business": count_rows(connection, "owner_business_marker"),
            "audits": count_rows(connection, "audit_events"),
            "encryptions": len(encryptions),
            "results": count_rows(connection, "idempotency_results"),
            "ledger_preserved": (
                connection.execute("SELECT * FROM idempotency_cipher_nonces").fetchall()
                == ledger_before
            ),
        }
        first = store.complete(owner_a, reservation, mutation("a"))
        replay = store.complete(
            owner_a,
            reservation,
            lambda: pytest.fail("owner A replay re-entered callback"),
        )
        result_rows = connection.execute(
            "SELECT workspace_id, principal, operation, key_hash, "
            "request_fingerprint, response_nonce FROM idempotency_results"
        ).fetchall()

        assert after_denied == {
            "error": "idempotency unavailable",
            "body": None,
            "callbacks": (),
            "business": 0,
            "audits": 0,
            "encryptions": 0,
            "results": 0,
            "ledger_preserved": True,
        }
        assert {
            "callbacks": tuple(callbacks),
            "business": count_rows(connection, "owner_business_marker"),
            "audits": count_rows(connection, "audit_events"),
            "encryptions": len(encryptions),
            "results": len(result_rows),
            "reservations": count_rows(connection, "idempotency_cipher_nonces"),
            "key_slots": store.key_version_state("primary").reserved_encryption_slots,
            "exact_replay": replay == first,
            "result_owner": tuple(result_rows[0][:5]) if result_rows else None,
            "result_nonce_matches": (
                len(result_rows) == 1 and result_rows[0][5] == reservation.nonce
            ),
        } == {
            "callbacks": ("a",),
            "business": 1,
            "audits": 1,
            "encryptions": 1,
            "results": 1,
            "reservations": 1,
            "key_slots": 1,
            "exact_replay": True,
            "result_owner": owner_a.reservation_owner_identity,
            "result_nonce_matches": True,
        }
    finally:
        connection.close()


def test_sqlite_nonce_ledger_row_cannot_back_two_result_owners(
    tmp_path: Path,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "nonce-single-use.sqlite")
    owner_a = invocation()
    owner_b = replace(
        owner_a,
        principal="agent:b",
        key_hash=b"b" * 32,
        request_fingerprint=b"B" * 32,
    )
    try:
        reservation = store.reserve_nonce(owner_a, now_epoch=100)
        store.complete(owner_a, reservation, outcome)

        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO idempotency_results "
                "(workspace_id, principal, operation, key_hash, request_fingerprint, "
                "format_version, status_code, cipher_key_version, response_nonce, "
                "response_ciphertext, created_at_epoch, expires_at_epoch) "
                "SELECT ?, ?, ?, ?, ?, format_version, status_code, "
                "cipher_key_version, response_nonce, response_ciphertext, "
                "created_at_epoch, expires_at_epoch FROM idempotency_results "
                "WHERE workspace_id = ? AND principal = ? "
                "AND operation = ? AND key_hash = ?",
                (
                    *owner_b.reservation_owner_identity,
                    *owner_a.result_identity,
                ),
            )

        assert count_rows(connection, "idempotency_results") == 1
        assert count_rows(connection, "idempotency_cipher_nonces") == 1
    finally:
        connection.close()
