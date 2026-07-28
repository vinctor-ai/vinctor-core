from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest
from idempotency_sqlite_fixtures import (
    configured_executor,
    count_rows,
    invocation,
    outcome,
)

from vinctor_service.idempotency_models import IdempotencyWriteUnavailable
from vinctor_service.idempotency_storage import terminal_expiry_epoch


def test_terminal_expiry_defaults_and_caps_at_24_hours() -> None:
    request = invocation()

    assert (
        terminal_expiry_epoch(
            replace(request, max_terminal_ttl_seconds=-1),
            now_epoch=100,
            replay_not_after_epoch=None,
        )
        == 86_500
    )
    assert (
        terminal_expiry_epoch(
            replace(request, max_terminal_ttl_seconds=172_800),
            now_epoch=100,
            replay_not_after_epoch=None,
        )
        == 86_500
    )


def test_terminal_expiry_is_capped_by_token_replay_deadline() -> None:
    assert (
        terminal_expiry_epoch(
            invocation(),
            now_epoch=100,
            replay_not_after_epoch=150,
        )
        == 150
    )


def test_sqlite_reservation_records_its_permanent_slot(tmp_path: Path) -> None:
    connection, store, _executor = configured_executor(tmp_path / "slot.sqlite")
    try:
        reservation = store.reserve_nonce(invocation(), now_epoch=100)
        assert reservation.slot == 1
    finally:
        connection.close()


@pytest.mark.parametrize(
    "forgery",
    ("missing_nonce", "wrong_reserved_at"),
)
def test_sqlite_phase_two_rejects_forged_reservation_before_side_effects(
    tmp_path: Path,
    forgery: str,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / f"{forgery}.sqlite")
    callback_count = 0
    try:
        request = invocation()
        reservation = store.reserve_nonce(request, now_epoch=100)
        if forgery == "missing_nonce":
            forged = replace(reservation, nonce=b"x" * 12)
        else:
            forged = replace(reservation, reserved_at_epoch=101)

        def mutation():
            nonlocal callback_count
            callback_count += 1
            return outcome()

        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            store.complete(request, forged, mutation)

        assert callback_count == 0
        assert count_rows(connection, "idempotency_cipher_nonces") == 1
        assert count_rows(connection, "idempotency_results") == 0
        assert count_rows(connection, "audit_events") == 0
    finally:
        connection.close()
