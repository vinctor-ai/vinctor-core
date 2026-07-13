"""Storage-op tamper-evidence trace (design:
docs/superpowers/specs/2026-07-13-storage-ops-audit-trace-design.md).

Every operator storage op (backup/reset/restore/migrate) must leave a trace to
BOTH stderr and the configured anchor BEFORE its destructive step, carrying the
op name, an ISO-8601 UTC timestamp, and the pre-op audit chain head.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest

from vinctor_core.models import AuditEvent
from vinctor_service.audit_anchor import (
    FileAnchor,
    NullAnchor,
    StdoutAnchor,
)
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.storage_ops import (
    backup_sqlite,
    migrate_sqlite,
    read_audit_chain_head,
    reset_sqlite,
    restore_sqlite,
)

GENESIS = "0" * 64
NOW = datetime(2026, 7, 13, 12, 0, tzinfo=UTC)


# --- Anchor sinks: emit_storage_op ------------------------------------------


def test_null_anchor_storage_op_is_noop() -> None:
    NullAnchor().emit_storage_op("reset", "2026-07-13T00:00:00+00:00", 3, "a" * 64)


def test_file_anchor_appends_storage_op_json_line(tmp_path) -> None:
    path = tmp_path / "anchor.log"
    a = FileAnchor(str(path))
    a.emit_storage_op("reset", "t1", 3, "h3")
    a.emit_storage_op("backup", "t2", 0, GENESIS)
    lines = path.read_text().splitlines()
    assert [json.loads(x) for x in lines] == [
        {"kind": "storage_op", "op": "reset", "at": "t1", "head_seq": 3, "head_hash": "h3"},
        {"kind": "storage_op", "op": "backup", "at": "t2", "head_seq": 0, "head_hash": GENESIS},
    ]


def test_file_anchor_storage_op_lines_coexist_with_chain_lines(tmp_path) -> None:
    # A single anchor file carries both record kinds; chain-head lines keep
    # their exact pre-existing shape (no "kind" key).
    path = tmp_path / "anchor.log"
    a = FileAnchor(str(path))
    a.emit(1, "h1", "t1")
    a.emit_storage_op("reset", "t2", 1, "h1")
    chain, storage = [json.loads(x) for x in path.read_text().splitlines()]
    assert chain == {"seq": 1, "row_hash": "h1", "created_at": "t1"}
    assert storage["kind"] == "storage_op" and storage["op"] == "reset"


def test_file_anchor_storage_op_is_fail_open_on_write_error(tmp_path) -> None:
    # A directory path can't be opened for appending -> must NOT raise.
    FileAnchor(str(tmp_path)).emit_storage_op("reset", "t1", 1, "h1")


def test_stdout_anchor_storage_op_writes_json_line(capsys) -> None:
    StdoutAnchor().emit_storage_op("migrate", "t1", 2, "h2")
    out = capsys.readouterr().out
    assert json.loads(out) == {
        "kind": "storage_op",
        "op": "migrate",
        "at": "t1",
        "head_seq": 2,
        "head_hash": "h2",
    }


# --- Test helpers ------------------------------------------------------------


def _event(event_id: str) -> AuditEvent:
    return AuditEvent(
        event_id=event_id, event_type="action_permitted", decision="permit",
        reason="ok", workspace_id="ws_main", agent_id="agent_a", grant_id="grnt_1",
        grant_ref="grt_1", action="read", resource="repo/x",
        scope_attempted="read:repo/x", scope_matched="read:repo/*",
        boundary_id="bnd_1", runtime="claude-code", boundary_type="pretooluse",
        created_at=NOW,
    )


def _init_db(db_path: Path, events: int = 0) -> None:
    conn = sqlite3.connect(db_path)
    try:
        init_sqlite_schema(conn)
        writer = SQLiteAuditWriter(conn)
        for i in range(events):
            writer.write(_event(f"evt_{i + 1}"))
    finally:
        conn.close()


def _db_head(db_path: Path) -> tuple[int, str]:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    return (row[0], row[1]) if row else (0, GENESIS)


class _SpyAnchor:
    def __init__(self) -> None:
        self.storage_ops: list[tuple[str, str, int | None, str | None]] = []

    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        return None

    def emit_storage_op(
        self, op: str, at: str, head_seq: int | None, head_hash: str | None
    ) -> None:
        self.storage_ops.append((op, at, head_seq, head_hash))


class _BoomAnchor:
    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        raise RuntimeError("sink down")

    def emit_storage_op(
        self, op: str, at: str, head_seq: int | None, head_hash: str | None
    ) -> None:
        raise RuntimeError("sink down")


def _run_op(op: str, tmp_path: Path, **kwargs):
    db = tmp_path / "vinctor.sqlite"
    if op == "backup":
        return backup_sqlite(db, tmp_path / "out.sqlite", **kwargs)
    if op == "reset":
        return reset_sqlite(db, **kwargs)
    if op == "restore":
        snap = tmp_path / "snap.sqlite"
        _init_db(snap)
        return restore_sqlite(db, snap, **kwargs)
    return migrate_sqlite(db, **kwargs)


def _trace_records(err: str) -> list[dict]:
    prefix = "vinctor: storage-op trace "
    return [
        json.loads(line[len(prefix):])
        for line in err.splitlines()
        if line.startswith(prefix)
    ]


OPS = ("backup", "reset", "restore", "migrate")


# --- read_audit_chain_head ----------------------------------------------------


def test_read_audit_chain_head_populated(tmp_path) -> None:
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=2)
    seq, head_hash = read_audit_chain_head(db)
    assert (seq, head_hash) == _db_head(db)
    assert seq == 2 and len(head_hash) == 64 and head_hash != GENESIS


def test_read_audit_chain_head_empty_chain_reports_genesis(tmp_path) -> None:
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=0)
    assert read_audit_chain_head(db) == (0, GENESIS)


def test_read_audit_chain_head_missing_db_reports_genesis(tmp_path) -> None:
    assert read_audit_chain_head(tmp_path / "missing.sqlite") == (0, GENESIS)


def test_read_audit_chain_head_does_not_create_db(tmp_path) -> None:
    db = tmp_path / "vinctor.sqlite"
    read_audit_chain_head(db)
    assert not db.exists()


# --- Trace to stderr: always, for every op, even with anchoring off -----------


@pytest.mark.parametrize("op", OPS)
def test_storage_op_writes_stderr_trace_even_with_null_anchor(
    op: str, tmp_path, capsys, monkeypatch
) -> None:
    monkeypatch.delenv("VINCTOR_AUDIT_ANCHOR", raising=False)  # anchor off -> NullAnchor
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=2)
    expected_head = _db_head(db)

    _run_op(op, tmp_path)

    records = _trace_records(capsys.readouterr().err)
    assert len(records) == 1
    rec = records[0]
    assert rec["kind"] == "storage_op" and rec["op"] == op
    assert (rec["head_seq"], rec["head_hash"]) == expected_head
    at = datetime.fromisoformat(rec["at"])
    assert at.utcoffset() is not None and at.utcoffset().total_seconds() == 0


# --- Trace to the anchor -------------------------------------------------------


@pytest.mark.parametrize("op", OPS)
def test_storage_op_emits_record_to_injected_anchor(op: str, tmp_path) -> None:
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=2)
    expected_head = _db_head(db)
    spy = _SpyAnchor()

    _run_op(op, tmp_path, anchor=spy)

    assert len(spy.storage_ops) == 1
    got_op, got_at, got_seq, got_hash = spy.storage_ops[0]
    assert got_op == op and (got_seq, got_hash) == expected_head
    assert datetime.fromisoformat(got_at).utcoffset().total_seconds() == 0


def test_env_configured_file_anchor_receives_storage_op_record(
    tmp_path, monkeypatch
) -> None:
    anchor_path = tmp_path / "anchor.log"
    monkeypatch.setenv("VINCTOR_AUDIT_ANCHOR", f"file:{anchor_path}")
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=1)
    expected_head = _db_head(db)

    reset_sqlite(db)

    lines = [json.loads(x) for x in anchor_path.read_text().splitlines()]
    assert len(lines) == 1
    assert lines[0]["kind"] == "storage_op" and lines[0]["op"] == "reset"
    assert (lines[0]["head_seq"], lines[0]["head_hash"]) == expected_head


# --- Pre-op head is captured BEFORE the destructive step -----------------------


def test_reset_trace_captures_pre_reset_head_before_destruction(tmp_path) -> None:
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=3)
    pre_head = _db_head(db)
    assert pre_head[0] == 3
    spy = _SpyAnchor()

    reset_sqlite(db, anchor=spy)

    # The local chain is gone...
    assert _db_head(db) == (0, GENESIS)
    # ...but the anchored record still holds the pre-reset head.
    assert spy.storage_ops[0][:1] + spy.storage_ops[0][2:] == ("reset", *pre_head)


def test_restore_trace_captures_pre_restore_head_of_target(tmp_path) -> None:
    target = tmp_path / "vinctor.sqlite"
    snap = tmp_path / "snap.sqlite"
    _init_db(target, events=3)
    _init_db(snap, events=1)
    pre_head = _db_head(target)
    snap_head = _db_head(snap)
    assert pre_head != snap_head
    spy = _SpyAnchor()

    restore_sqlite(target, snap, anchor=spy)

    # The target's chain was replaced by the snapshot's...
    assert _db_head(target) == snap_head
    # ...but the anchored record holds the head the target had BEFORE the restore.
    op, _at, head_seq, head_hash = spy.storage_ops[0]
    assert op == "restore" and (head_seq, head_hash) == pre_head


# --- Fail-open ------------------------------------------------------------------


@pytest.mark.parametrize("op", OPS)
def test_storage_op_proceeds_when_anchor_raises(op: str, tmp_path, capsys) -> None:
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=1)

    result = _run_op(op, tmp_path, anchor=_BoomAnchor())  # must NOT raise

    assert result.schema_versions  # the op completed
    err = capsys.readouterr().err
    assert len(_trace_records(err)) == 1  # stderr trace still fired
    assert "storage-op anchor emit raised" in err and "sink down" in err


def test_storage_op_proceeds_when_head_read_fails(tmp_path, capsys) -> None:
    db = tmp_path / "vinctor.sqlite"
    db.write_text("stale-not-a-db", encoding="utf-8")  # unreadable as SQLite
    spy = _SpyAnchor()

    reset_sqlite(db, anchor=spy)  # must NOT raise

    err = capsys.readouterr().err
    assert "storage-op head read failed" in err
    records = _trace_records(err)
    assert len(records) == 1
    # Head unknown (could not be read) is reported as explicit nulls, never
    # silently claimed empty.
    assert records[0]["head_seq"] is None and records[0]["head_hash"] is None
    assert spy.storage_ops == [(records[0]["op"], records[0]["at"], None, None)]
    assert _db_head(db) == (0, GENESIS)  # reset still completed


def test_backup_trace_emitted_even_when_validation_fails(tmp_path, capsys) -> None:
    # The trace records the ATTEMPT: it fires at op entry, before validation.
    with pytest.raises(FileNotFoundError):
        backup_sqlite(tmp_path / "missing.sqlite", tmp_path / "out.sqlite", anchor=_SpyAnchor())
    records = _trace_records(capsys.readouterr().err)
    assert len(records) == 1 and records[0]["op"] == "backup"


# --- CLI integration -----------------------------------------------------------


def _run_cli(argv: list[str]) -> tuple[int, str]:
    from vinctor_service.cli import run_vinctor

    stdout, stderr = StringIO(), StringIO()
    status = run_vinctor(argv, stdout=stdout, stderr=stderr)
    return status, stdout.getvalue()


def test_cli_storage_reset_emits_trace_to_env_anchor(tmp_path, monkeypatch) -> None:
    anchor_path = tmp_path / "anchor.log"
    monkeypatch.setenv("VINCTOR_AUDIT_ANCHOR", f"file:{anchor_path}")
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=2)
    pre_head = _db_head(db)

    status, _out = _run_cli(["--db", str(db), "operator", "storage", "reset", "--yes"])

    assert status == 0
    assert _db_head(db) == (0, GENESIS)  # chain wiped locally...
    lines = [json.loads(x) for x in anchor_path.read_text().splitlines()]
    assert len(lines) == 1  # ...but the anchor holds the pre-reset head.
    assert lines[0]["kind"] == "storage_op" and lines[0]["op"] == "reset"
    assert (lines[0]["head_seq"], lines[0]["head_hash"]) == pre_head


def test_cli_audit_verify_against_anchor_skips_storage_op_records(tmp_path) -> None:
    db = tmp_path / "vinctor.sqlite"
    _init_db(db, events=2)
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT seq, row_hash, created_at FROM audit_events ORDER BY seq"
        ).fetchall()
    finally:
        conn.close()

    anchor_path = tmp_path / "anchor.log"
    sink = FileAnchor(str(anchor_path))
    sink.emit(rows[0][0], rows[0][1], rows[0][2])
    sink.emit_storage_op("backup", "2026-07-13T00:00:00+00:00", rows[0][0], rows[0][1])
    sink.emit(rows[1][0], rows[1][1], rows[1][2])

    status, out = _run_cli(
        ["--db", str(db), "operator", "audit", "verify",
         "--against-anchor", str(anchor_path), "-o", "json"]
    )

    assert status == 0
    parsed = json.loads(out)
    assert parsed["ok"] is True
    # Only the two chain-head records count; the storage-op record is not a
    # chain assertion and must be skipped, not crash the parser.
    assert parsed["anchor"]["ok"] is True and parsed["anchor"]["checked"] == 2
