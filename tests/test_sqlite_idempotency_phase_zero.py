from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from idempotency_sqlite_fixtures import (
    configured_executor,
    count_rows,
    invocation,
)
from idempotency_sqlite_store_scenarios import (
    _seed_completed_result,
    exercise_expired_historical_key_reuse,
    exercise_phase_zero_conflict,
    exercise_phase_zero_expired,
    exercise_phase_zero_observation_replay,
    exercise_phase_zero_replay,
    exercise_phase_zero_unavailable,
)

from vinctor_service.idempotency_models import (
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
)
from vinctor_service.sqlite_txn import connect_sqlite

if TYPE_CHECKING:
    pass

def test_sqlite_phase_zero_replay_consumes_no_reservation(tmp_path: Path) -> None:
    # Given one completed SQLite idempotency result.
    # When the same invocation is replayed.
    result = exercise_phase_zero_replay(tmp_path / "replay.sqlite3")
    # Then exact replay bypasses the callback and consumes no reservation.
    assert result.exact_response is True
    assert result.callback_count == 0
    assert result.reservations_after == result.reservations_before

def test_sqlite_phase_zero_replay_preserves_authenticated_observation(
    tmp_path: Path,
) -> None:
    # Given one encrypted response with non-default typed observation fields.
    # When the same invocation is replayed.
    result = exercise_phase_zero_observation_replay(tmp_path / "observation.sqlite3")
    # Then replay preserves the complete response without callback or reservation burn.
    assert (
        result.exact_response,
        result.callback_count,
        result.reservations_after == result.reservations_before,
    ) == (True, 0, True)

def test_sqlite_phase_zero_conflict_is_typed_and_consumes_no_reservation(
    tmp_path: Path,
) -> None:
    # Given one unexpired completed result under the same scoped key.
    # When an invocation presents a different canonical request fingerprint.
    result = exercise_phase_zero_conflict(tmp_path / "conflict.sqlite3")
    # Then the store returns a typed conflict without callback, slot burn, or row loss.
    assert (
        result.typed_error,
        result.callback_count,
        result.reservations_after == result.reservations_before,
        result.result_count,
    ) == (True, 0, True, 1)

@pytest.mark.parametrize(
    "fault",
    ("corrupt", "expiry_metadata", "fingerprint_metadata", "unknown_key"),
)
def test_sqlite_phase_zero_unavailable_is_coarse_and_preserves_authoritative_row(
    tmp_path: Path,
    fault: str,
) -> None:
    # Given an authoritative row with unreadable ciphertext or unauthenticated metadata.
    # When Phase 0 attempts an exact replay.
    result = exercise_phase_zero_unavailable(
        tmp_path / f"unavailable-{fault}.sqlite3",
        fault,
    )
    # Then one coarse typed failure preserves the row and performs no callback or burn.
    assert (
        result.typed_error,
        result.callback_count,
        result.reservations_after == result.reservations_before,
        result.result_count,
    ) == (True, 0, True, 1)

def test_sqlite_phase_zero_malformed_input_is_coarse_and_consumes_no_reservation(
    tmp_path: Path,
) -> None:
    connection, _, executor = configured_executor(tmp_path / "malformed.sqlite3")
    try:
        with pytest.raises(IdempotencyWriteUnavailable, match="idempotency unavailable"):
            executor.execute(
                invocation(key_hash=b"k" * 31),
                lambda: pytest.fail("malformed input entered callback"),
            )
        assert (
            count_rows(connection, "idempotency_cipher_nonces"),
            count_rows(connection, "idempotency_results"),
        ) == (0, 0)
    finally:
        connection.close()

def test_sqlite_phase_zero_primary_unavailable_is_one_coarse_error(
    tmp_path: Path,
) -> None:
    database = tmp_path / "primary-unavailable.sqlite3"
    connection, _, executor = configured_executor(database)
    connection.close()
    with pytest.raises(IdempotencyResultUnavailable, match="idempotency unavailable"):
        executor.execute(
            invocation(),
            lambda: pytest.fail("unavailable primary entered callback"),
        )
    reopened = connect_sqlite(database)
    try:
        assert (
            count_rows(reopened, "idempotency_cipher_nonces"),
            count_rows(reopened, "idempotency_results"),
        ) == (0, 0)
    finally:
        reopened.close()

def test_sqlite_phase_zero_expired_result_proceeds_to_a_fresh_reservation(
    tmp_path: Path,
) -> None:
    result = exercise_phase_zero_expired(tmp_path / "expired.sqlite3")
    assert (
        result.typed_error,
        result.callback_count,
        result.reservations_after,
        result.result_count,
    ) == (False, 1, result.reservations_before + 1, 1)

def test_sqlite_gc_preserves_expiry_tamper_and_fails_closed(tmp_path: Path) -> None:
    # Given an authentic completed row whose authenticated expiry is tampered into the past.
    connection, store, _executor = configured_executor(tmp_path / "gc-tamper.sqlite3")
    try:
        _seed_completed_result(connection, store)
        connection.execute(
            "UPDATE idempotency_results SET created_at_epoch = 0, expires_at_epoch = 1"
        )
        connection.commit()

        # When bounded GC considers the row.
        with pytest.raises(IdempotencyResultUnavailable):
            store.gc_expired_results(limit=100)

        # Then the unauthenticated candidate is preserved.
        assert count_rows(connection, "idempotency_results") == 1
    finally:
        connection.close()

def test_sqlite_expired_result_rejects_unsafe_historical_key_removal(
    tmp_path: Path,
) -> None:
    result = exercise_expired_historical_key_reuse(
        tmp_path / "expired-retired-key.sqlite3"
    )

    assert (
        result.unavailable,
        result.callback_count,
        result.result_count,
        result.reservation_count,
    ) == (True, 0, 1, 1)
