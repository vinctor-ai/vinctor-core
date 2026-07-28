from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from idempotency_sqlite_fixtures import audit_event, count_rows

from vinctor_core.models import AuditEvent
from vinctor_service.audit import record_rejection
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


class RecordingAnchor:
    def __init__(self) -> None:
        self.emissions: list[tuple[int, str, str]] = []

    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        self.emissions.append((seq, row_hash, created_at))

    def emit_storage_op(
        self,
        op: str,
        at: str,
        head_seq: int | None,
        head_hash: str | None,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class BestEffortFailureOutcome:
    write_succeeded: bool
    outer_query_result: tuple[int]
    audit_count: int
    emission_count: int


def exercise_duplicate_best_effort_write(database: Path) -> BestEffortFailureOutcome:
    connection = connect_sqlite(database)
    init_sqlite_schema(connection)
    anchor = RecordingAnchor()
    writer = SQLiteAuditWriter(connection, anchor=anchor)
    event = audit_event()
    writer.write(event)
    anchor.emissions.clear()
    try:
        with connection:
            write_succeeded = writer.write_best_effort(event)
            row = connection.execute("SELECT 1").fetchone()
        assert row is not None
        return BestEffortFailureOutcome(
            write_succeeded=write_succeeded,
            outer_query_result=(int(row[0]),),
            audit_count=count_rows(connection, "audit_events"),
            emission_count=len(anchor.emissions),
        )
    finally:
        connection.close()


def exercise_record_rejection(database: Path) -> int:
    connection = connect_sqlite(database)
    init_sqlite_schema(connection)
    writer = SQLiteAuditWriter(connection)

    def fail_authoritative_write(_event: AuditEvent) -> None:
        raise RuntimeError("authoritative writer must not be used for rejection")

    writer.write = fail_authoritative_write
    try:
        record_rejection(writer, audit_event("evt_rejection"))
        return count_rows(connection, "audit_events")
    finally:
        connection.close()
