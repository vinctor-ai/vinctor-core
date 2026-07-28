from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from idempotency_sqlite_fixtures import audit_event, count_rows

from vinctor_core.models import AuditEvent
from vinctor_service.audit import record_rejection
from vinctor_service.audit_export import ExportingAuditWriter
from vinctor_service.postgres import PostgresAuditWriter
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite

FAULTS = ("setup", "audit_write", "rollback_to", "release", "cleanup_release")


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


def test_write_only_audit_writer_uses_safe_fallback_even_when_export_sink_raises() -> None:
    class WriteOnly:
        def __init__(self) -> None:
            self.events: list[AuditEvent] = []

        def write(self, event: AuditEvent) -> None:
            self.events.append(event)

    class RaisingExport:
        def emit(self, _event: AuditEvent) -> None:
            raise RuntimeError("sink unavailable")

    durable = WriteOnly()
    writer = ExportingAuditWriter(durable, RaisingExport())

    assert record_rejection(writer, audit_event("evt_write_only")) is True
    assert [event.event_id for event in durable.events] == ["evt_write_only"]


@pytest.mark.parametrize("fault", FAULTS)
def test_sqlite_best_effort_fault_matrix_preserves_outer_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    connection = connect_sqlite(tmp_path / f"sqlite-{fault}.sqlite3")
    init_sqlite_schema(connection)
    anchor = RecordingAnchor()
    writer = SQLiteAuditWriter(connection, anchor=anchor)
    original_execute = connection.execute
    original_getattr = SerializedSQLiteConnection.__getattr__
    original_write = writer._write_event
    injected = False

    def faulted_execute(statement: str, parameters=()):
        nonlocal injected
        normalized = " ".join(statement.split()).upper()
        target = {
            "setup": normalized.startswith("SAVEPOINT "),
            "rollback_to": normalized.startswith("ROLLBACK TO SAVEPOINT "),
            "release": normalized.startswith("RELEASE SAVEPOINT "),
            "cleanup_release": normalized.startswith("RELEASE SAVEPOINT "),
        }.get(fault, False)
        if target and not injected:
            injected = True
            raise RuntimeError(f"{fault} fault")
        return original_execute(statement, parameters)

    def faulted_getattr(self: SerializedSQLiteConnection, name: str):
        if self is connection and name == "execute":
            return faulted_execute
        return original_getattr(self, name)

    def faulted_write(event: AuditEvent) -> tuple[int, str, str]:
        if fault == "audit_write":
            raise RuntimeError("audit write fault")
        result = original_write(event)
        if fault in {"rollback_to", "cleanup_release"}:
            raise RuntimeError("audit write fault after insert")
        return result

    monkeypatch.setattr(SerializedSQLiteConnection, "__getattr__", faulted_getattr)
    monkeypatch.setattr(writer, "_write_event", faulted_write)
    try:
        connection.execute("BEGIN IMMEDIATE")
        assert writer.write_best_effort(audit_event(f"evt_sqlite_{fault}")) is False
        assert connection.execute("SELECT 1").fetchone() == (1,)
        connection.commit()
        assert count_rows(connection, "audit_events") == 0
        assert anchor.emissions == []
    finally:
        connection.close()


class FakePostgresAuditConnection:
    def __init__(self, fault: str) -> None:
        self.fault = fault
        self.depth = 0
        self.audit_rows = 0
        self.scheduled_emissions = 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        nested = self.depth > 0
        snapshot = self.audit_rows
        if nested and self.fault == "setup":
            raise RuntimeError("setup fault")
        self.depth += 1
        try:
            yield
        except Exception:
            self.audit_rows = snapshot
            self.depth -= 1
            if nested and self.fault in {"rollback_to", "cleanup_release"}:
                raise RuntimeError(f"{self.fault} fault") from None
            raise
        else:
            self.depth -= 1
            if nested and self.fault == "release":
                self.audit_rows = snapshot
                raise RuntimeError("release fault")

    def execute(self, statement: str, parameters=()):
        if statement == "SELECT 1":
            return FakeCursor((1,))
        raise AssertionError((statement, parameters))

    def emit_or_defer(self, emission: Callable[[], None]) -> None:
        self.scheduled_emissions += 1
        emission()


class FakeCursor:
    def __init__(self, row: tuple[int]) -> None:
        self._row = row

    def fetchone(self) -> tuple[int]:
        return self._row


@pytest.mark.parametrize("fault", FAULTS)
def test_postgres_best_effort_fault_matrix_preserves_outer_transaction(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
) -> None:
    connection = FakePostgresAuditConnection(fault)
    anchor = RecordingAnchor()
    writer = PostgresAuditWriter(connection, anchor=anchor)

    def faulted_write(_event: AuditEvent) -> tuple[int, str, str]:
        if fault == "audit_write":
            raise RuntimeError("audit write fault")
        connection.audit_rows += 1
        if fault in {"rollback_to", "cleanup_release"}:
            raise RuntimeError("audit write fault after insert")
        return 1, "hash", "created"

    monkeypatch.setattr(writer, "_write_event", faulted_write)
    with connection.transaction():
        assert writer.write_best_effort(audit_event(f"evt_postgres_{fault}")) is False
        assert connection.execute("SELECT 1").fetchone() == (1,)

    assert connection.audit_rows == 0
    assert connection.scheduled_emissions == 0
    assert anchor.emissions == []
