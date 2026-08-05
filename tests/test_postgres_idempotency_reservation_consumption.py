from __future__ import annotations

from dataclasses import replace

import pytest
from idempotency_postgres_fixtures import invocation, outcome
from idempotency_postgres_phase2_fake_support import FakeStore, keyring, reservation

from vinctor_service import idempotency_postgres_completion as completion
from vinctor_service.idempotency_models import (
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyKeyVersion,
    IdempotencyKeyVersionLabel,
    IdempotencyWriteUnavailable,
)

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


def _fake_result(owner, reserved: CryptoReservation) -> tuple[object, ...]:
    return (
        owner.request_fingerprint,
        1,
        201,
        reserved.version,
        reserved.nonce,
        b"x" * 16,
        1,
        4_102_444_800,
    )


def test_postgres_fake_consumed_reservation_stays_burned_after_result_gc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(keyring())
    owner = invocation()
    reserved = reservation()
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    real_encrypt = completion.encrypt_reserved_response
    store.fake_connection.reservation_claimed_at_epoch = None

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

    def mutation(generation: str):
        def run():
            callbacks.append(generation)
            return outcome(f'{{"generation":"{generation}"}}'.encode())

        return run

    store.complete(owner, reserved, mutation("first"))
    store.fake_connection.result_rows.clear()
    before = (tuple(callbacks), tuple(encryptions))

    with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
        store.complete(owner, reserved, mutation("old-reuse"))

    assert (tuple(callbacks), tuple(encryptions)) == before
    fresh = CryptoReservation(
        IdempotencyKeyVersionLabel("primary"),
        2,
        b"m" * 12,
        101,
    )
    store.fake_connection.reservation = (
        *fresh.ledger_identity,
        *owner.reservation_owner_identity,
    )
    store.fake_connection.reservation_claimed_at_epoch = None
    response = store.complete(owner, fresh, mutation("fresh"))
    assert response.body == b'{"generation":"fresh"}'
    assert callbacks == ["first", "fresh"]
    assert encryptions == [reserved.nonce, fresh.nonce]


def test_postgres_fake_result_failure_keeps_claim_and_rejects_same_reservation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(keyring())
    owner = invocation()
    reserved = reservation()
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
    store.fake_connection.fail_result_insert = True

    with pytest.raises(IdempotencyWriteUnavailable) as captured:
        store.complete(owner, reserved, mutation)
    assert captured.value.__cause__ is None

    store.fake_connection.fail_result_insert = False
    before_retry = (tuple(callbacks), tuple(encryptions))
    with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
        store.complete(owner, reserved, mutation)

    assert store.fake_connection.reservation_claimed_at_epoch == 100
    assert (
        (tuple(callbacks), tuple(encryptions))
        == before_retry
        == (
            ("called",),
            (reserved.nonce,),
        )
    )
    fresh = CryptoReservation(
        IdempotencyKeyVersionLabel("primary"),
        2,
        b"m" * 12,
        101,
    )
    store.fake_connection.reservation = (
        *fresh.ledger_identity,
        *owner.reservation_owner_identity,
    )
    store.fake_connection.reservation_claimed_at_epoch = None
    assert store.complete(owner, fresh, mutation).body == b'{"ok":true}'


@pytest.mark.parametrize("state", INCONSISTENT_STATES)
def test_postgres_fake_inconsistent_consumption_state_is_denied_before_effects(
    monkeypatch: pytest.MonkeyPatch,
    state: str,
) -> None:
    store = FakeStore(keyring())
    owner = invocation()
    other = _other_owner()
    reserved = reservation()
    callbacks: list[str] = []
    encryptions: list[bytes] = []
    real_encrypt = completion.encrypt_reserved_response
    store.fake_connection.reservation_claimed_at_epoch = None

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
        return outcome()

    if state == "consumed_no_result":
        store.fake_connection.reservation_claimed_at_epoch = 100
    elif state.startswith("unconsumed_"):
        result_owner = owner if "same_owner" in state else other
        store.fake_connection.result_rows[result_owner.result_identity] = _fake_result(
            result_owner,
            reserved,
        )
    else:
        store.complete(owner, reserved, mutation)
        callbacks.clear()
        encryptions.clear()
        store.fake_connection.reservation_claimed_at_epoch = 100
        row = store.fake_connection.result_rows.pop(owner.result_identity)
        if state.endswith("owner_mismatch"):
            store.fake_connection.result_rows[other.result_identity] = (
                other.request_fingerprint,
                *row[1:],
            )
        else:
            store.fake_connection.result_rows[owner.result_identity] = (
                *row[:4],
                b"x" * 12,
                *row[5:],
            )
    before_rows = dict(store.fake_connection.result_rows)

    with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
        store.complete(owner, reserved, mutation)

    assert callbacks == []
    assert encryptions == []
    assert store.fake_connection.result_rows == before_rows
