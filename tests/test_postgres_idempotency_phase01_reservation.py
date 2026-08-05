from __future__ import annotations

import pytest
from idempotency_postgres_contention_scenarios import (
    exercise_postgres_slot_contention,
)
from idempotency_postgres_fixtures import configured_postgres_executor, invocation
from idempotency_postgres_phase01_process import (
    exercise_abrupt_first_misses,
    exercise_concurrent_first_misses,
)
from idempotency_postgres_phase01_results import phase_zero_counts

from vinctor_service.idempotency_models import IdempotencyWriteUnavailable


def test_postgres_phase_one_repeated_abrupt_exit_preserves_distinct_reservations(
    requires_postgres: str,
) -> None:
    result = exercise_abrupt_first_misses(requires_postgres)

    assert result.exit_codes == (17, 17)
    assert result.reserved_slots == 2
    assert result.nonces == (b"\x11" * 12, b"\x22" * 12)
    assert result.callback_count == 0
    assert result.rollback_marker_count == 0
    assert result.result_count == 0
    assert result.audit_count == 0


def test_postgres_phase_one_concurrent_first_misses_each_reserve_once(
    requires_postgres: str,
) -> None:
    result = exercise_concurrent_first_misses(requires_postgres)

    assert result.exit_codes == (0, 0)
    assert result.reserved_slots == 2
    assert result.nonces == (b"\x33" * 12, b"\x44" * 12)
    assert result.callback_count == 0
    assert result.rollback_marker_count == 0
    assert result.result_count == 0
    assert result.audit_count == 0


def test_postgres_phase_one_nonce_collision_rolls_back_and_disables_key(
    requires_postgres: str,
) -> None:
    nonce = b"n" * 12
    connection, store, _ = configured_postgres_executor(
        requires_postgres,
        nonce_factory=lambda size: nonce if size == 12 else b"",
    )
    try:
        now_epoch = store.database_epoch()
        first = store.reserve_nonce(invocation(), now_epoch=now_epoch)

        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            store.reserve_nonce(invocation(), now_epoch=now_epoch)

        state = store.key_version_state("primary")
        counts = phase_zero_counts(connection)
        assert str(captured.value) == "idempotency unavailable"
        assert first.nonce == nonce
        assert state.reserved_encryption_slots == 1
        assert state.write_disabled_reason == "nonce_collision"
        assert counts.nonces == 1
        assert counts.results == counts.audits == 0
    finally:
        connection.close()


def test_postgres_phase_one_hard_cap_contention_never_exceeds_limit(
    requires_postgres: str,
) -> None:
    result = exercise_postgres_slot_contention(requires_postgres)

    assert result.threads_finished
    assert result.accepted == 1
    assert result.rejected == 1
    assert result.reserved_slots == 2**24
    assert result.nonce_count == 1
    assert result.disabled_reason == "hard_limit"
