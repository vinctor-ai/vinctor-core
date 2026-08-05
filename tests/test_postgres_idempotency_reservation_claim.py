from __future__ import annotations

import pytest
from idempotency_postgres_fixtures import configured_postgres_executor, invocation, outcome

from vinctor_service import idempotency_postgres_completion as completion
from vinctor_service.idempotency_models import (
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyWriteUnavailable,
)


def test_postgres_result_insert_rollback_keeps_claim_and_rejects_same_reservation(
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

    def mutation():
        callbacks.append("called")
        return outcome()

    monkeypatch.setattr(completion, "encrypt_reserved_response", counted_encrypt)
    try:
        with connection.transaction():
            connection.execute(
                "CREATE OR REPLACE FUNCTION vinctor_fail_claim_result() "
                "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
                "RAISE EXCEPTION 'forced result insert failure'; END $$"
            )
            connection.execute(
                "CREATE TRIGGER fail_claim_result BEFORE INSERT ON idempotency_results "
                "FOR EACH ROW EXECUTE FUNCTION vinctor_fail_claim_result()"
            )
        reservation = store.reserve_nonce(owner, now_epoch=store.database_epoch())

        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            store.complete(owner, reservation, mutation)
        assert captured.value.__cause__ is None

        claimed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = %s AND nonce = %s",
            (reservation.version, reservation.nonce),
        ).fetchone()
        connection.commit()
        with connection.transaction():
            connection.execute("DROP TRIGGER fail_claim_result ON idempotency_results")
            connection.execute("DROP FUNCTION vinctor_fail_claim_result()")
        before_retry = (tuple(callbacks), tuple(encryptions))

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(owner, reservation, mutation)

        assert claimed is not None and claimed[0] is not None
        assert (
            (tuple(callbacks), tuple(encryptions))
            == before_retry
            == (
                ("called",),
                (reservation.nonce,),
            )
        )
        fresh = store.reserve_nonce(owner, now_epoch=store.database_epoch())
        assert store.complete(owner, fresh, mutation).body == b'{"ok":true}'
        assert fresh.nonce != reservation.nonce
    finally:
        with connection.transaction():
            connection.execute("DROP TRIGGER IF EXISTS fail_claim_result ON idempotency_results")
            connection.execute("DROP FUNCTION IF EXISTS vinctor_fail_claim_result()")
        connection.close()
