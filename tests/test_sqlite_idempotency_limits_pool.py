from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from idempotency_sqlite_pool_scenarios import (
    exercise_barrier_recovery,
    exercise_quarantine,
    exercise_rebuild,
    exercise_replacement_failure,
    exercise_shared_pool,
    exercise_shutdown,
)
from idempotency_sqlite_store_scenarios import (
    exercise_gc,
    exercise_nonce_collision,
    exercise_nonce_ledger_gc,
    exercise_slot_boundaries,
)

if TYPE_CHECKING:
    pass

def test_sqlite_nonce_collision_rolls_back_increment_and_commits_disable_barrier(
    tmp_path: Path,
) -> None:
    # Given a deterministic nonce factory that collides on the second reservation.
    # When the store detects the unique-ledger conflict.
    result = exercise_nonce_collision(tmp_path / "collision.sqlite3")
    # Then the increment rolls back and an independent disable barrier commits.
    assert (result.raised, result.reserved_slots, result.disabled_reason) == (
        True,
        1,
        "nonce_collision",
    )

def test_sqlite_soft_and_hard_slot_boundaries_are_exact(tmp_path: Path) -> None:
    # Given exact persisted counters immediately below soft and at hard limits.
    # When a real reservation is attempted at each boundary.
    result = exercise_slot_boundaries(tmp_path / "limits.sqlite3")
    # Then soft reporting occurs at 2^23 and 2^24 rejects.
    assert (result.soft_reported_epoch, result.hard_limit_raised) == (100, True)

def test_sqlite_expiry_uses_db_time_and_gc_deletes_at_most_100(tmp_path: Path) -> None:
    # Given 101 expired encrypted results.
    # When bounded GC uses database time.
    result = exercise_gc(tmp_path / "gc.sqlite3")
    # Then exactly 100 rows are deleted.
    assert (result.deleted, result.remaining_results) == (100, 1)

def test_sqlite_nonce_ledger_is_never_result_gc_or_reclaimed(tmp_path: Path) -> None:
    # Given a burned nonce followed by result GC.
    # When the durable ledger is counted directly.
    nonce_count = exercise_nonce_ledger_gc(tmp_path / "nonce-ledger.sqlite3")
    # Then the reservation is never reclaimed.
    assert nonce_count == 1

def test_sqlite_pool_shares_keyring_signal_and_uses_connection_bound_executors(
    tmp_path: Path,
) -> None:
    # Given two concurrent leases from one configured SQLite service pool.
    # When each leased service executes a distinct keyed mutation.
    result = exercise_shared_pool(tmp_path / "pool-shared.sqlite3")
    # Then executors are connection-bound while the process keyring is shared.
    assert (
        result.distinct_connections,
        result.distinct_keyrings,
        result.connection_bound_executors,
        result.callback_count,
    ) == (2, 1, 2, 2)

def test_sqlite_ambiguous_commit_quarantines_lease_and_never_requeues_old_generation(
    tmp_path: Path,
) -> None:
    # Given a current pool lease whose commit outcome becomes ambiguous.
    # When the next request obtains a healthy replacement lease.
    result = exercise_quarantine(tmp_path / "quarantine.sqlite3")
    # Then the old generation is closed and cannot be requeued.
    assert result.replacement_generation > result.old_generation
    assert result.old_connection_closed is True

def test_sqlite_pool_rebuilds_connection_service_and_keys_with_shared_process_state(
    tmp_path: Path,
) -> None:
    # Given a quarantined size-one context.
    # When pool capacity is restored.
    result = exercise_rebuild(tmp_path / "replace.sqlite3")
    # Then connection/service/keys are rebuilt and process state is preserved.
    assert result.connection_rebuilt is True
    assert result.service_rebuilt is True
    assert result.keys_rebuilt is True
    assert result.process_state_shared is True

def test_sqlite_pool_replacement_failure_reduces_capacity_and_turns_readiness_false(
    tmp_path: Path,
) -> None:
    # Given a pool whose injected replacement connection factory fails.
    # When the current context is quarantined and cannot be replaced.
    result = exercise_replacement_failure(tmp_path / "replace-fail.sqlite3")
    # Then capacity stays reduced and readiness fails closed.
    assert (result.raised, result.capacity, result.ready) == (True, 0, False)

def test_sqlite_pool_shutdown_closes_quarantined_and_replacement_connections_once(
    tmp_path: Path,
) -> None:
    # Given one quarantined connection and its pool-created replacement.
    # When shutdown is requested twice.
    result = exercise_shutdown(tmp_path / "shutdown.sqlite3")
    # Then each physical connection closes exactly once.
    assert (result.old_close_count, result.replacement_close_count) == (1, 1)

def test_sqlite_barrier_ambiguity_uses_one_shot_fresh_authority_without_callback(
    tmp_path: Path,
) -> None:
    # Given a pool and a callback that must never run during barrier recovery.
    # When fresh one-shot authority completes an ambiguous write-disable barrier.
    result = exercise_barrier_recovery(tmp_path / "barrier.sqlite3")
    # Then the barrier is durable without producing a business result.
    assert (result.write_disabled, result.result_count) == (True, 0)
