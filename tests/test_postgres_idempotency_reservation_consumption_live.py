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

from vinctor_service import idempotency_postgres_completion as completion
from vinctor_service.idempotency_models import (
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyWriteUnavailable,
)

MARKER_TABLE = "idempotency_consumption_marker"
INCONSISTENT_STATES = (
    "consumed_no_result",
    "unconsumed_same_owner_result",
    "unconsumed_cross_owner_result",
    "consumed_result_owner_mismatch",
    "consumed_result_nonce_mismatch",
)


def _other_owner():
    return replace(
        invocation(),
        principal="agent:b",
        key_hash=b"b" * 32,
        request_fingerprint=b"B" * 32,
    )


def _create_marker(connection) -> None:
    with connection.transaction():
        connection.execute(f'DROP TABLE IF EXISTS "{MARKER_TABLE}"')
        connection.execute(f'CREATE TABLE "{MARKER_TABLE}" (generation TEXT NOT NULL UNIQUE)')


def _drop_marker(connection) -> None:
    with connection.transaction():
        connection.execute(f'DROP TABLE IF EXISTS "{MARKER_TABLE}"')


def _insert_result(connection, owner, reserved: CryptoReservation) -> None:
    with connection.transaction():
        connection.execute(
            "INSERT INTO idempotency_results "
            "(workspace_id, principal, operation, key_hash, request_fingerprint, "
            "format_version, status_code, cipher_key_version, response_nonce, "
            "response_ciphertext, created_at_epoch, expires_at_epoch) "
            "VALUES (%s, %s, %s, %s, %s, 1, 201, %s, %s, %s, 1, 4102444800)",
            (
                *owner.reservation_owner_identity,
                reserved.version,
                reserved.nonce,
                b"x" * 16,
            ),
        )


def test_postgres_consumed_reservation_stays_burned_after_result_gc(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, _executor = configured_postgres_executor(requires_postgres)
    owner = invocation()
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

    def mutation(generation: str, *, replay_not_after_epoch: int | None = None):
        def run():
            callbacks.append(generation)
            connection.execute(
                f'INSERT INTO "{MARKER_TABLE}"(generation) VALUES (%s)',
                (generation,),
            )
            store.audit_writer.write(audit_event(f"evt_pg_reservation_{generation}"))
            return replace(
                outcome(f'{{"generation":"{generation}"}}'.encode()),
                replay_not_after_epoch=replay_not_after_epoch,
            )

        return run

    try:
        _create_marker(connection)
        now_epoch = store.database_epoch()
        old = store.reserve_nonce(owner, now_epoch=now_epoch - 2)
        with monkeypatch.context() as patch:
            patch.setattr(completion, "postgres_database_epoch", lambda _connection: now_epoch - 2)
            store.complete(
                owner,
                old,
                mutation("first", replay_not_after_epoch=now_epoch - 1),
            )
        assert store.gc_expired_results(limit=100) == 1
        before = (
            tuple(callbacks),
            tuple(encryptions),
            count_rows(connection, MARKER_TABLE),
            count_rows(connection, "audit_events"),
        )
        connection.rollback()

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(owner, old, mutation("old-reuse"))

        assert (
            tuple(callbacks),
            tuple(encryptions),
            count_rows(connection, MARKER_TABLE),
            count_rows(connection, "audit_events"),
        ) == before
        connection.rollback()
        fresh = store.reserve_nonce(owner, now_epoch=store.database_epoch())
        store.complete(owner, fresh, mutation("fresh"))
        assert callbacks == ["first", "fresh"]
        assert encryptions == [old.nonce, fresh.nonce]
        assert old.nonce != fresh.nonce
    finally:
        _drop_marker(connection)
        connection.close()


@pytest.mark.parametrize("state", INCONSISTENT_STATES)
def test_postgres_inconsistent_consumption_state_is_denied_before_effects(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    connection, store, _executor = configured_postgres_executor(requires_postgres)
    owner = invocation()
    other = _other_owner()
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

    def mutation():
        callbacks.append("ran")
        connection.execute(f'INSERT INTO "{MARKER_TABLE}"(generation) VALUES (%s)', ("ran",))
        store.audit_writer.write(audit_event("evt_pg_inconsistent"))
        return outcome()

    try:
        _create_marker(connection)
        reserved = store.reserve_nonce(owner, now_epoch=store.database_epoch())
        if state == "consumed_no_result":
            now_epoch = store.database_epoch()
            with connection.transaction():
                connection.execute(
                    "UPDATE idempotency_cipher_nonces SET claimed_at_epoch = %s "
                    "WHERE cipher_key_version = %s AND nonce = %s",
                    (now_epoch, reserved.version, reserved.nonce),
                )
        elif state.startswith("unconsumed_"):
            _insert_result(
                connection,
                owner if "same_owner" in state else other,
                reserved,
            )
        else:
            store.complete(owner, reserved, mutation)
            callbacks.clear()
            encryptions.clear()
            with connection.transaction():
                if state.endswith("owner_mismatch"):
                    connection.execute(
                        "UPDATE idempotency_results SET principal = %s, key_hash = %s",
                        ("agent:b", b"b" * 32),
                    )
                else:
                    connection.execute(
                        "UPDATE idempotency_results SET response_nonce = %s",
                        (b"x" * 12,),
                    )
        before = (
            count_rows(connection, MARKER_TABLE),
            count_rows(connection, "audit_events"),
            count_rows(connection, "idempotency_results"),
            tuple(callbacks),
            tuple(encryptions),
        )
        connection.rollback()

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(owner, reserved, mutation)

        assert (
            count_rows(connection, MARKER_TABLE),
            count_rows(connection, "audit_events"),
            count_rows(connection, "idempotency_results"),
            tuple(callbacks),
            tuple(encryptions),
        ) == before
    finally:
        _drop_marker(connection)
        connection.close()
