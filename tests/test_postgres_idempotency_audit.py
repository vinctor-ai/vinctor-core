from __future__ import annotations

import pytest
from idempotency_postgres_audit_scenarios import (
    exercise_duplicate_best_effort_write,
    exercise_record_rejection,
)
from idempotency_postgres_contention_scenarios import (
    exercise_postgres_process_race,
    exercise_postgres_skip_locked_gc,
    exercise_postgres_slot_contention,
)
from idempotency_postgres_fixtures import (
    audit_event,
    configured_postgres_executor,
    count_rows,
    invocation,
    outcome,
)


def test_postgres_concurrent_first_misses_across_processes_run_one_callback(
    requires_postgres: str,
) -> None:
    result = exercise_postgres_process_race(requires_postgres)
    assert result.exit_codes == (0, 0)
    assert (result.callback_count, result.result_count) == (1, 1)

def test_postgres_best_effort_audit_savepoint_does_not_poison_outer_transaction(
    requires_postgres: str,
) -> None:
    # Given a duplicate event inside a live outer PostgreSQL transaction.
    result = exercise_duplicate_best_effort_write(requires_postgres)
    # When the backend-owned writer rolls back the failed nested savepoint.
    # Then the outer transaction stays usable and only the original event remains.
    assert (result.write_succeeded, result.outer_query_result, result.audit_count) == (
        False,
        (1,),
        1,
    )

def test_postgres_record_rejection_cannot_fall_back_to_self_suppressing_write(
    requires_postgres: str,
) -> None:
    # Given the concrete PostgreSQL best-effort audit writer.
    # When the shared rejection function records one event.
    count = exercise_record_rejection(requires_postgres)
    # Then the backend contains exactly the delegated write.
    assert count == 1

def test_postgres_best_effort_savepoint_schedules_no_anchor_or_export_after_failure(
    requires_postgres: str,
) -> None:
    # Given a duplicate best-effort write with a recording anchor.
    result = exercise_duplicate_best_effort_write(requires_postgres)
    # When the duplicate is rolled back to its savepoint.
    # Then no post-commit anchor/export-style emission is scheduled.
    assert (result.write_succeeded, result.emission_count) == (False, 0)

def test_postgres_authoritative_audit_failure_rolls_back_state_audit_and_result(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    monkeypatch.setattr(store.audit_writer, "write", lambda _event: 1 / 0)

    def mutation():
        store.audit_writer.write(audit_event("evt_authoritative"))
        return outcome()

    with pytest.raises(ZeroDivisionError):
        executor.execute(invocation(), mutation)
    assert count_rows(connection, "idempotency_results") == 0
    assert count_rows(connection, "idempotency_cipher_nonces") == 1
    connection.close()

def test_postgres_slot_guard_never_exceeds_hard_limit_across_connections(
    requires_postgres: str,
) -> None:
    result = exercise_postgres_slot_contention(requires_postgres)
    assert result.threads_finished is True
    assert (result.accepted, result.rejected) == (1, 1)
    assert (result.reserved_slots, result.nonce_count, result.disabled_reason) == (
        2**24,
        1,
        "hard_limit",
    )

def test_postgres_nonce_collision_commits_disable_on_fresh_transaction(
    requires_postgres: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store, _ = configured_postgres_executor(requires_postgres)
    monkeypatch.setattr(store, "nonce_factory", lambda _size: b"n" * 12)
    now_epoch = store.database_epoch()
    store.reserve_nonce(invocation(), now_epoch=now_epoch)
    with pytest.raises(RuntimeError):
        store.reserve_nonce(invocation(), now_epoch=now_epoch)
    assert store.key_version_state("primary").write_disabled_reason == "nonce_collision"

def test_postgres_gc_uses_skip_locked_and_deletes_at_most_100(
    requires_postgres: str,
) -> None:
    result = exercise_postgres_skip_locked_gc(requires_postgres)
    assert (result.deleted, result.remaining, result.locked_row_survived) == (100, 1, True)
