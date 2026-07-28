from __future__ import annotations

from dataclasses import replace

import pytest
from idempotency_postgres_fixtures import invocation, outcome
from idempotency_postgres_phase2_fake_support import (
    FakeStore,
    keyring,
    reservation,
)

from vinctor_service import idempotency_postgres_completion as completion
from vinctor_service.idempotency_models import (
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyConflict,
    IdempotencyKeyVersion,
    IdempotencyKeyVersionLabel,
    IdempotencyWriteUnavailable,
)


def test_postgres_phase_two_locks_before_recheck_and_replays_exact_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(keyring())
    encryption_nonces: list[bytes] = []
    callback_count = 0
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

    def mutation():
        nonlocal callback_count
        callback_count += 1
        return outcome(
            b'{"token":"opaque"}',
            error_code="terminal",
            decision="permit",
        )

    first = store.complete(invocation(), reservation(), mutation)
    replay = store.complete(
        invocation(),
        reservation(),
        lambda: pytest.fail("exact replay re-entered mutation"),
    )
    with pytest.raises(IdempotencyConflict):
        store.complete(
            invocation(fingerprint=b"x" * 32),
            reservation(),
            lambda: pytest.fail("conflict re-entered mutation"),
        )
    queries = store.fake_connection.queries
    lock_index = next(i for i, query in enumerate(queries) if "pg_advisory_xact_lock" in query)
    state_index = max(i for i, query in enumerate(queries) if "write_disabled_epoch" in query)
    result_index = max(i for i, query in enumerate(queries) if query.startswith("SELECT request"))

    assert lock_index < state_index < result_index
    assert callback_count == 1
    assert encryption_nonces == [b"n" * 12]
    assert replay == first
    assert replay.observation.error_code == "terminal"
    assert replay.observation.decision == "permit"


def test_postgres_disabled_reservation_burns_without_callback_or_encryption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(keyring())
    store.fake_connection.key_state = (100, None)
    monkeypatch.setattr(
        completion,
        "encrypt_reserved_response",
        lambda **_kwargs: pytest.fail("disabled reservation attempted encryption"),
    )

    with pytest.raises(IdempotencyWriteUnavailable):
        store.complete(
            invocation(),
            reservation(),
            lambda: pytest.fail("disabled reservation entered callback"),
        )


def test_postgres_result_insert_driver_error_is_coarse_and_rolls_back() -> None:
    store = FakeStore(keyring())
    store.fake_connection.fail_result_insert = True

    with pytest.raises(IdempotencyWriteUnavailable) as captured:
        store.complete(invocation(), reservation(), lambda: outcome())

    assert str(captured.value) == "idempotency unavailable"
    assert captured.value.__cause__ is None
    assert store.fake_connection.result_rows == {}
    assert store.fake_connection.reservation_claimed_at_epoch == 100
    assert store.fake_connection.transaction_depth == 0


@pytest.mark.parametrize(
    "forged",
    (
        replace(reservation(), version=IdempotencyKeyVersionLabel("secondary")),
        replace(reservation(), slot=2),
        replace(reservation(), nonce=b"x" * 12),
        replace(reservation(), reserved_at_epoch=100),
    ),
)
def test_postgres_phase_two_rejects_forged_reservation_before_side_effects(
    forged: CryptoReservation,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(keyring())
    monkeypatch.setattr(
        completion,
        "encrypt_reserved_response",
        lambda **_kwargs: pytest.fail("forged reservation attempted encryption"),
    )

    with pytest.raises(IdempotencyWriteUnavailable):
        store.complete(
            invocation(),
            forged,
            lambda: pytest.fail("forged reservation entered callback"),
        )

    assert store.fake_connection.result_rows == {}
    assert store.fake_connection.transaction_depth == 0


def test_postgres_gc_is_capped_and_uses_skip_locked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = FakeStore(keyring())
    monkeypatch.setattr(
        completion,
        "parse_completed_result_row",
        lambda _row: (invocation(), object()),
    )
    monkeypatch.setattr(
        completion,
        "classify_completed_result",
        lambda *_args, **_kwargs: completion.IdempotencyProceedToReservation(),
    )

    assert store.gc_expired_results(limit=10_000) == 100
    query = next(
        query
        for query in store.fake_connection.queries
        if "FOR UPDATE SKIP LOCKED" in query
    )
    assert "FOR UPDATE SKIP LOCKED LIMIT %s" in query
