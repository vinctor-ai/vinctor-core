from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from idempotency_sqlite_audit_scenarios import (
    exercise_duplicate_best_effort_write,
    exercise_record_rejection,
)
from idempotency_sqlite_fault_scenarios import (
    exercise_business_commit_fault,
    exercise_cipher_fault,
    exercise_result_insert_fault,
)
from idempotency_sqlite_fixtures import (
    audit_event,
    configured_executor,
    count_rows,
    invocation,
    outcome,
)

from vinctor_core.models import AuditEvent
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import CacheableTerminalOutcome

def test_sqlite_cipher_result_insert_and_business_commit_faults_roll_back_phase_two_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes = (
        exercise_cipher_fault(tmp_path / "cipher-fault.sqlite3", monkeypatch),
        exercise_result_insert_fault(tmp_path / "insert-fault.sqlite3"),
        exercise_business_commit_fault(tmp_path / "commit-fault.sqlite3"),
    )
    assert tuple(result.fault for result in outcomes) == (
        "cipher",
        "result_insert",
        "business_commit",
    )
    assert tuple(result.error_type for result in outcomes) == (
        "RuntimeError",
        "IdempotencyWriteUnavailable",
        "IdempotencyWriteUnavailable",
    )
    assert all(
        (
            result.business_rows,
            result.audit_rows,
            result.result_rows,
            result.nonce_rows,
        )
        == (0, 0, 0, 1)
        for result in outcomes
    )

def test_sqlite_best_effort_audit_failure_rolls_back_savepoint_and_commits_terminal_result(
    tmp_path: Path,
) -> None:
    # Given a duplicate event inside a live outer SQLite transaction.
    result = exercise_duplicate_best_effort_write(tmp_path / "best-effort.sqlite3")
    # When the backend-owned best-effort writer rolls back its savepoint.
    # Then the outer transaction remains usable and only the original event exists.
    assert (result.write_succeeded, result.outer_query_result, result.audit_count) == (
        False,
        (1,),
        1,
    )

def test_sqlite_record_rejection_delegates_to_backend_owned_best_effort_seam(
    tmp_path: Path,
) -> None:
    # Given the concrete SQLite best-effort audit writer.
    # When the shared rejection function records one event.
    count = exercise_record_rejection(tmp_path / "rejection.sqlite3")
    # Then the durable backend contains the delegated write.
    assert count == 1

def test_sqlite_best_effort_savepoint_schedules_no_anchor_or_export_after_failure(
    tmp_path: Path,
) -> None:
    # Given a duplicate best-effort write with a recording post-commit anchor.
    result = exercise_duplicate_best_effort_write(tmp_path / "emission.sqlite3")
    # When the duplicate row is rolled back to its savepoint.
    # Then no anchor/export-style emission is scheduled.
    assert (result.write_succeeded, result.emission_count) == (False, 0)

def test_sqlite_best_effort_savepoint_setup_failure_is_contained(tmp_path: Path) -> None:
    connection = connect_sqlite(tmp_path / "closed-best-effort.sqlite3")
    init_sqlite_schema(connection)
    writer = SQLiteAuditWriter(connection)
    connection.close()

    assert writer.write_best_effort(audit_event("evt_closed")) is False

def test_sqlite_authoritative_audit_failure_rolls_back_state_audit_and_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection, store, executor = configured_executor(tmp_path / "authoritative.sqlite3")

    def fail_authoritative(_event: AuditEvent) -> None:
        raise RuntimeError("authoritative audit fault")

    monkeypatch.setattr(store.audit_writer, "write", fail_authoritative)

    def mutation() -> CacheableTerminalOutcome:
        store.audit_writer.write(audit_event("evt_authoritative"))
        return outcome()

    with pytest.raises(RuntimeError):
        executor.execute(invocation(), mutation)
    assert count_rows(connection, "idempotency_results") == 0
    assert count_rows(connection, "idempotency_cipher_nonces") == 1
    connection.close()
