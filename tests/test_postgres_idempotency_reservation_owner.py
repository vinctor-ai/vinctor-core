from __future__ import annotations

from dataclasses import replace

import pytest
from idempotency_postgres_fixtures import (
    audit_event,
    configured_postgres_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_postgres_phase2_fake_support import FakeStore, keyring, reservation

from vinctor_service import idempotency_postgres_completion as completion
from vinctor_service.idempotency_models import (
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyWriteUnavailable,
)

MARKER_TABLE = "idempotency_owner_binding_marker"
OWNER_MISMATCHES = (
    ("workspace_id", "ws-b"),
    ("principal", "agent:b"),
    ("operation", "grant.revoke.v1"),
    ("key_hash", b"b" * 32),
    ("request_fingerprint", b"B" * 32),
)


@pytest.mark.parametrize(("owner_field", "foreign_value"), OWNER_MISMATCHES)
def test_postgres_fake_reservation_cannot_complete_a_different_owner(
    monkeypatch: pytest.MonkeyPatch,
    owner_field: str,
    foreign_value: str | bytes,
) -> None:
    store = FakeStore(keyring())
    owner_a = invocation()
    owner_b = replace(owner_a, **{owner_field: foreign_value})
    store.fake_connection.reservation = (
        *reservation().ledger_identity,
        *owner_a.reservation_owner_identity,
    )
    callbacks: list[str] = []
    business: list[str] = []
    audits: list[str] = []
    encryption_nonces: list[bytes] = []
    real_encrypt = completion.encrypt_reserved_response

    def counted_encrypt(
        *,
        key: IdempotencyKeyVersion,
        reservation: CryptoReservation,
        plaintext: bytes,
        aad: bytes,
    ) -> EncryptedResponseEnvelope:
        encryption_nonces.append(reservation.nonce)
        return real_encrypt(
            key=key,
            reservation=reservation,
            plaintext=plaintext,
            aad=aad,
        )

    monkeypatch.setattr(completion, "encrypt_reserved_response", counted_encrypt)

    def mutation(owner: str):
        def run():
            callbacks.append(owner)
            business.append(owner)
            audits.append(owner)
            return outcome(f'{{"owner":"{owner}"}}'.encode())

        return run

    with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
        store.complete(owner_b, reservation(), mutation("b"))
    assert {
        "callbacks": callbacks,
        "business": business,
        "audits": audits,
        "encryptions": encryption_nonces,
        "results": store.fake_connection.result_rows,
    } == {
        "callbacks": [],
        "business": [],
        "audits": [],
        "encryptions": [],
        "results": {},
    }

    first = store.complete(owner_a, reservation(), mutation("a"))
    replay = store.complete(
        owner_a,
        reservation(),
        lambda: pytest.fail("owner A replay re-entered callback"),
    )
    assert {
        "callbacks": callbacks,
        "business": business,
        "audits": audits,
        "encryptions": encryption_nonces,
        "results": len(store.fake_connection.result_rows),
        "exact_replay": replay == first,
    } == {
        "callbacks": ["a"],
        "business": ["a"],
        "audits": ["a"],
        "encryptions": [reservation().nonce],
        "results": 1,
        "exact_replay": True,
    }


@pytest.mark.parametrize(("owner_field", "foreign_value"), OWNER_MISMATCHES)
def test_postgres_reservation_cannot_complete_a_different_owner(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
    owner_field: str,
    foreign_value: str | bytes,
) -> None:
    connection, store, _executor = configured_postgres_executor(requires_postgres)
    with connection.transaction():
        connection.execute(f'DROP TABLE IF EXISTS "{MARKER_TABLE}"')
        connection.execute(f'CREATE TABLE "{MARKER_TABLE}" (value INTEGER NOT NULL)')
    owner_a = invocation()
    owner_b = replace(owner_a, **{owner_field: foreign_value})
    reservation = store.reserve_nonce(owner_a, now_epoch=store.database_epoch())
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    real_encrypt = completion.encrypt_reserved_response

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

    monkeypatch.setattr(completion, "encrypt_reserved_response", counted_encrypt)

    def mutation(owner: str, value: int):
        def run():
            callbacks.append(owner)
            connection.execute(f'INSERT INTO "{MARKER_TABLE}"(value) VALUES (%s)', (value,))
            store.audit_writer.write(audit_event(f"evt_postgres_owner_{owner}"))
            return outcome(f'{{"owner":"{owner}"}}'.encode())

        return run

    try:
        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(owner_b, reservation, mutation("b", 2))
        assert {
            "callbacks": callbacks,
            "business": count_rows(connection, MARKER_TABLE),
            "audits": count_rows(connection, "audit_events"),
            "encryptions": encryptions,
            "results": count_rows(connection, "idempotency_results"),
            "reservations": count_rows(connection, "idempotency_cipher_nonces"),
        } == {
            "callbacks": [],
            "business": 0,
            "audits": 0,
            "encryptions": [],
            "results": 0,
            "reservations": 1,
        }
        connection.rollback()

        first = store.complete(owner_a, reservation, mutation("a", 1))
        replay = store.complete(
            owner_a,
            reservation,
            lambda: pytest.fail("owner A replay re-entered callback"),
        )
        nonce_rows = connection.execute("SELECT response_nonce FROM idempotency_results").fetchall()
        assert {
            "callbacks": callbacks,
            "business": count_rows(connection, MARKER_TABLE),
            "audits": count_rows(connection, "audit_events"),
            "encryptions": encryptions,
            "results": len(nonce_rows),
            "reservations": count_rows(connection, "idempotency_cipher_nonces"),
            "exact_replay": replay == first,
            "result_nonce_matches": (
                len(nonce_rows) == 1 and bytes(nonce_rows[0][0]) == reservation.nonce
            ),
        } == {
            "callbacks": ["a"],
            "business": 1,
            "audits": 1,
            "encryptions": [reservation.nonce],
            "results": 1,
            "reservations": 1,
            "exact_replay": True,
            "result_nonce_matches": True,
        }
    finally:
        with connection.transaction():
            connection.execute(f'DROP TABLE IF EXISTS "{MARKER_TABLE}"')
        connection.close()
