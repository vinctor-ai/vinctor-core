from __future__ import annotations

from pathlib import Path

from idempotency_sqlite_store_scenarios import (
    exercise_concurrent_first_misses,
    exercise_durable_reservation,
    exercise_loser_replay,
    exercise_process_race,
)


def test_sqlite_phase_one_commit_precedes_callback_and_survives_process_crash(
    tmp_path: Path,
) -> None:
    # Given one child process that exits immediately after its Phase 1 commit.
    # When the parent opens an independent connection after the child has crashed.
    result = exercise_durable_reservation(tmp_path / "reserve.sqlite3")
    # Then the crashed process's committed nonce exists before any callback can run.
    assert (result.exit_code, result.reservation_count, result.nonce_matches) == (17, 1, True)

def test_sqlite_concurrent_first_misses_may_burn_distinct_reservations(
    tmp_path: Path,
) -> None:
    result = exercise_concurrent_first_misses(tmp_path / "first-misses.sqlite3")
    assert result.exit_codes == (0, 0)
    assert (
        result.callback_count,
        result.result_count,
        result.reservation_count,
        result.distinct_nonce_count,
    ) == (1, 1, 2, 2)

def test_sqlite_phase_two_mandatory_recheck_selects_one_callback_across_processes(
    tmp_path: Path,
) -> None:
    # Given two independently spawned processes racing one missing key.
    # When both cross the mandatory Phase 2 recheck.
    result = exercise_process_race(tmp_path / "race.sqlite3")
    # Then both finish, but only one callback and one result persist.
    assert result.exit_codes == (0, 0)
    assert (result.callback_count, result.result_count) == (1, 1)

def test_sqlite_loser_burns_reservation_and_replays_without_audit_retry(
    tmp_path: Path,
) -> None:
    # Given a winner followed by an exact losing/replay attempt.
    # When both use the real executor.
    result = exercise_loser_replay(tmp_path / "loser.sqlite3")
    # Then callback/result/reservation counts remain exactly one.
    assert (
        result.callback_count,
        result.result_count,
        result.reservation_count,
    ) == (1, 1, 1)
