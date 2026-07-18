import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from vinctor_core.models import AuditEvent
from vinctor_service.audit_chain import GENESIS_PREV_HASH, AnchorRecord, row_hash
from vinctor_service.sqlite import (
    SQLiteAuditWriter,
    get_sqlite_schema_versions,
    init_sqlite_schema,
)
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _raw_event_row(conn, event_id, seq_hint, workspace="ws_main"):
    """Insert a pre-chain audit row (NULL chain columns) directly, as a legacy DB
    would have. created_at ordered by seq_hint so rowid order == intended order."""
    ev = AuditEvent(
        event_id=event_id, event_type="action_permitted", decision="permit",
        reason="ok", workspace_id=workspace, agent_id="agent_a", grant_id="grnt_1",
        grant_ref="grt_1", action="read", resource="repo/x",
        scope_attempted="read:repo/x", scope_matched="read:repo/*",
        boundary_id="bnd_1", runtime="claude-code", boundary_type="pretooluse",
        created_at=NOW + timedelta(seconds=seq_hint),
    )
    conn.execute(
        "INSERT INTO audit_events (event_id,event_type,decision,reason,workspace_id,"
        "agent_id,grant_id,grant_ref,action,resource,scope_attempted,scope_matched,"
        "boundary_id,runtime,boundary_type,created_at,event_json) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (ev.event_id, ev.event_type, ev.decision, ev.reason, ev.workspace_id,
         ev.agent_id, ev.grant_id, ev.grant_ref, ev.action, ev.resource,
         ev.scope_attempted, ev.scope_matched, ev.boundary_id, ev.runtime,
         ev.boundary_type, ev.created_at.isoformat(),
         json.dumps(ev.to_dict(), sort_keys=True)),
    )
    conn.commit()


def test_migration_adds_columns_and_registers_v11(tmp_path) -> None:
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert {"seq", "prev_hash", "row_hash"} <= cols
    assert 11 in get_sqlite_schema_versions(conn)


def test_backfill_chains_existing_rows_from_genesis(tmp_path) -> None:
    # Simulate a legacy DB: create the schema WITHOUT chain columns, insert rows,
    # then re-run init_sqlite_schema to migrate + back-fill.
    conn = connect_sqlite(tmp_path / "legacy.sqlite")
    conn.executescript(
        "CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,"
        " decision TEXT NOT NULL, reason TEXT NOT NULL, workspace_id TEXT NOT NULL,"
        " agent_id TEXT NOT NULL, grant_id TEXT NOT NULL, grant_ref TEXT NOT NULL,"
        " action TEXT NOT NULL, resource TEXT NOT NULL, scope_attempted TEXT NOT NULL,"
        " scope_matched TEXT, boundary_id TEXT, runtime TEXT, boundary_type TEXT,"
        " created_at TEXT NOT NULL, event_json TEXT NOT NULL);"
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);"
    )
    _raw_event_row(conn, "evt_1", 1)
    _raw_event_row(conn, "evt_2", 2)

    init_sqlite_schema(conn)  # migrates + back-fills

    rows = conn.execute(
        "SELECT seq, prev_hash, row_hash, event_json FROM audit_events ORDER BY seq"
    ).fetchall()
    assert [r[0] for r in rows] == [1, 2]
    assert rows[0][1] == GENESIS_PREV_HASH
    assert rows[0][2] == row_hash(1, rows[0][3], GENESIS_PREV_HASH)
    assert rows[1][1] == rows[0][2]
    assert rows[1][2] == row_hash(2, rows[1][3], rows[0][2])


def _writer(tmp_path):
    conn = connect_sqlite(tmp_path / "w.sqlite")
    init_sqlite_schema(conn)
    return conn, SQLiteAuditWriter(conn)


def _event(event_id: str) -> AuditEvent:
    return AuditEvent(
        event_id=event_id, event_type="action_permitted", decision="permit",
        reason="ok", workspace_id="ws_main", agent_id="agent_a", grant_id="grnt_1",
        grant_ref="grt_1", action="read", resource="repo/x",
        scope_attempted="read:repo/x", scope_matched="read:repo/*",
        boundary_id="bnd_1", runtime="claude-code", boundary_type="pretooluse",
        created_at=NOW,
    )


def test_write_assigns_gapless_seq_and_valid_chain(tmp_path) -> None:
    conn, w = _writer(tmp_path)
    w.write(_event("evt_1"))
    w.write(_event("evt_2"))
    w.write(_event("evt_3"))
    rows = conn.execute(
        "SELECT seq, prev_hash, row_hash, event_json FROM audit_events ORDER BY seq"
    ).fetchall()
    assert [r[0] for r in rows] == [1, 2, 3]
    assert rows[0][1] == GENESIS_PREV_HASH
    prev = GENESIS_PREV_HASH
    for seq, prev_hash, rh, ej in rows:
        assert prev_hash == prev
        assert rh == row_hash(seq, ej, prev_hash)
        prev = rh


def _seed_three(tmp_path):
    conn, w = _writer(tmp_path)
    for i in (1, 2, 3):
        w.write(_event(f"evt_{i}"))
    return conn, w


def test_verify_ok_on_untouched_chain(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    v = w.verify_chain()
    assert v.ok is True and v.count == 3 and v.head_seq == 3


def test_verify_detects_modified_event_json(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    # Forge a deny->permit by editing event_json of seq 2 (row hash now stale).
    forged = json.dumps({**_event("evt_2").to_dict(), "decision": "deny"}, sort_keys=True)
    conn.execute("UPDATE audit_events SET event_json = ? WHERE seq = 2", (forged,))
    conn.commit()
    v = w.verify_chain()
    assert v.ok is False and v.break_seq == 2 and v.break_kind == "modified"


def test_verify_detects_deleted_row(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    conn.execute("DELETE FROM audit_events WHERE seq = 2")
    conn.commit()
    v = w.verify_chain()
    assert v.ok is False and v.break_kind == "deleted" and v.break_seq == 2


def test_verify_detects_column_mismatch(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    # Edit only the denormalized filter column, leaving event_json (and the hash) intact.
    conn.execute("UPDATE audit_events SET workspace_id = 'ws_other' WHERE seq = 2")
    conn.commit()
    v = w.verify_chain()
    assert v.ok is False and v.break_kind == "column_mismatch" and v.break_seq == 2


def test_verify_detects_created_at_column_tamper(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    # Backdate only the materialized timestamp column; event_json and row_hash stay intact.
    tampered = (NOW + timedelta(hours=6)).isoformat()
    conn.execute("UPDATE audit_events SET created_at = ? WHERE seq = 2", (tampered,))
    conn.commit()
    v = w.verify_chain()
    assert v.ok is False and v.break_kind == "column_mismatch" and v.break_seq == 2


def test_verify_ok_when_created_at_spelled_as_equivalent_instant(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    # Same instant, different ISO-8601 offset spelling. The cross-check must compare
    # instants, not raw strings — Postgres returns TIMESTAMPTZ in the session
    # timezone, so string-identity would false-positive on healthy chains.
    same_instant = NOW.astimezone(timezone(timedelta(hours=9))).isoformat()
    conn.execute("UPDATE audit_events SET created_at = ? WHERE seq = 2", (same_instant,))
    conn.commit()
    assert w.verify_chain().ok is True


def _full_event(event_id: str) -> AuditEvent:
    # Every optional/ADR-0007/ADR-0008 field populated: exercises the crosscheck
    # normalization paths (datetime, bool, int, nullable text) on a healthy chain.
    return replace(
        _event(event_id),
        enforcing_principal="usr_owner",
        reason_code="unmapped_action",
        occurrence_count=4,
        first_seen_at=NOW - timedelta(minutes=30),
        last_seen_at=NOW - timedelta(minutes=1),
        identity_proven=True,
        token_id="stk_1",
    )


def test_verify_ok_with_all_optional_fields_populated(tmp_path) -> None:
    conn, w = _writer(tmp_path)
    w.write(_event("evt_1"))
    w.write(_full_event("evt_2"))
    w.write(_event("evt_3"))
    v = w.verify_chain()
    assert v.ok is True and v.count == 3 and v.head_seq == 3


def test_chain_head_reports_tip_and_genesis_when_empty(tmp_path) -> None:
    conn, w = _writer(tmp_path)
    assert w.chain_head() == (0, GENESIS_PREV_HASH)
    w.write(_event("evt_1"))
    seq, h = w.chain_head()
    assert seq == 1 and len(h) == 64


def test_verify_against_anchor_ok_and_detects_rewrite(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    anchors = [AnchorRecord(seq=s, row_hash=w._conn.execute(
        "SELECT row_hash FROM audit_events WHERE seq = ?", (s,)).fetchone()[0])
        for s in (1, 2, 3)]
    assert w.verify_against_anchor(anchors).ok is True
    # Rewrite seq 2's content + rechain the tail so verify_chain() alone would pass...
    forged = json.dumps({**_event("evt_2").to_dict(), "decision": "deny"}, sort_keys=True)
    prev1 = w._conn.execute("SELECT row_hash FROM audit_events WHERE seq=1").fetchone()[0]
    rh2 = row_hash(2, forged, prev1)
    ej3 = w._conn.execute("SELECT event_json FROM audit_events WHERE seq=3").fetchone()[0]
    rh3 = row_hash(3, ej3, rh2)
    # Also update the denormalized `decision` column so the forged row is FULLY
    # internally consistent (event_json, hash, AND crosschecked columns all agree);
    # otherwise verify_chain's column-crosscheck would catch it first and the anchor
    # defense being tested here would never be exercised.
    conn.execute(
        "UPDATE audit_events SET event_json=?, row_hash=?, decision='deny' WHERE seq=2",
        (forged, rh2),
    )
    conn.execute("UPDATE audit_events SET prev_hash=?, row_hash=? WHERE seq=3", (rh2, rh3))
    conn.commit()
    assert w.verify_chain().ok is True                      # internally consistent now
    av = w.verify_against_anchor(anchors)                    # ...but the anchor disagrees
    assert av.ok is False and av.divergence_seq == 2 and av.divergence_kind == "mismatch"


def test_write_emits_head_to_injected_anchor(tmp_path) -> None:
    conn = connect_sqlite(tmp_path / "a.sqlite")
    init_sqlite_schema(conn)
    emitted = []

    class _CaptureAnchor:
        def emit(self, seq, row_hash, created_at):
            emitted.append((seq, row_hash))

    w = SQLiteAuditWriter(conn, anchor=_CaptureAnchor())
    w.write(_event("evt_1"))
    assert len(emitted) == 1 and emitted[0][0] == 1


def test_write_is_fail_open_when_anchor_raises(tmp_path) -> None:
    conn = connect_sqlite(tmp_path / "b.sqlite")
    init_sqlite_schema(conn)

    class _BoomAnchor:
        def emit(self, seq, row_hash, created_at):
            raise RuntimeError("sink down")

    w = SQLiteAuditWriter(conn, anchor=_BoomAnchor())
    w.write(_event("evt_1"))  # must NOT raise
    # The row is still written + chained despite the anchor failure.
    assert w.verify_chain().ok is True and w.chain_head()[0] == 1


def test_chain_stays_valid_under_concurrent_enforce(tmp_path) -> None:
    # The chain's head-read-then-insert is safe across pooled connections because
    # every standalone write scope starts with BEGIN IMMEDIATE. Hammer a real
    # service, then verify the resulting chain is gapless and unbroken. Mirrors
    # tests/test_local_http_concurrency.py.
    import json as _json
    import urllib.request
    from concurrent.futures import ThreadPoolExecutor
    from threading import Thread

    from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service

    db_path = tmp_path / "conc.sqlite"
    handle = prepare_local_service(
        LocalLaunchConfig(db_path=db_path, port=0, scopes=("read:test/*",))
    )
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()

    def _enforce_once(_i: int) -> int:
        body = _json.dumps(
            {"grant_ref": handle.grant_ref, "action": "read", "resource": "test/file"}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{handle.endpoint}/v1/enforce",
            data=body,
            headers={"Content-Type": "application/json", "X-Agent-Key": handle.agent_key},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status

    try:
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(_enforce_once, range(400)))
        assert all(s == 200 for s in statuses)
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()

    conn = connect_sqlite(db_path)
    v = SQLiteAuditWriter(conn).verify_chain()
    # 402 = the `scope_bounds_set` control event + the `grant_issued` event
    # that prepare_local_service writes while bootstrapping the local grant,
    # plus the 400 concurrent enforce events. The invariant under test is that
    # the chain is valid and gapless (count == head_seq) despite concurrency,
    # not the exact bootstrap count.
    assert v.ok is True and v.count == 402 and v.head_seq == 402


def test_postgres_crosscheck_columns_match_sqlite() -> None:
    # Both backends MUST cross-check the same materialized columns against
    # event_json during verify_chain, or one backend would miss a tampering the
    # other catches. Guards drift without needing a live Postgres.
    from vinctor_service.postgres import PostgresAuditWriter

    assert PostgresAuditWriter._CROSSCHECK_COLUMNS == SQLiteAuditWriter._CROSSCHECK_COLUMNS


def test_crosscheck_covers_every_sqlite_materialized_event_json_column(tmp_path) -> None:
    # Every audit_events column that mirrors an event_json field must be in the
    # cross-check set, or a DB-write attacker could edit the materialized copy
    # without breaking verification. (Chain/bookkeeping columns and event_json
    # itself are covered by the row hash instead.)
    conn = connect_sqlite(tmp_path / "cols.sqlite")
    init_sqlite_schema(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert cols - {"event_json", "seq", "prev_hash", "row_hash"} == set(
        SQLiteAuditWriter._CROSSCHECK_COLUMNS
    )


def test_postgres_crosschecks_every_pg_only_materialized_column() -> None:
    # Postgres additionally materializes these event_json fields as dedicated
    # columns that list_filtered reads directly (SQLite filters them via
    # json_extract over the hash-protected event_json and has no such columns
    # to tamper with). Each one must be cross-checked during verify_chain, or an
    # attacker could hide/re-classify events for Postgres readers — e.g. flip
    # reason_code or identity_proven — while verification still passes.
    from vinctor_service.postgres import PostgresAuditWriter

    assert PostgresAuditWriter._PG_ONLY_CROSSCHECK_COLUMNS == (
        "enforcing_principal", "reason_code", "occurrence_count",
        "first_seen_at", "last_seen_at", "identity_proven", "token_id",
    )
    assert set(PostgresAuditWriter._PG_ONLY_CROSSCHECK_COLUMNS).isdisjoint(
        PostgresAuditWriter._CROSSCHECK_COLUMNS
    )


# --- B2: audit ordering / backfill integrity -----------------------------


def test_backfill_is_one_time_and_does_not_reheal_post_migration_null(tmp_path) -> None:
    """After the migration sentinel is recorded, a NULL row_hash is tampering,
    not un-migrated data: re-running init must NOT silently re-chain it (which
    would mask the tamper) — verify_chain fails closed instead.

    Power: nulling the LAST row's hash is exactly what the old ungated backfill
    would recompute back to the valid value, making verify_chain pass again.
    """
    conn, w = _writer(tmp_path)  # fresh DB: migration sentinel v14 recorded
    for i in (1, 2, 3):
        w.write(_event(f"evt_{i}"))

    # Tamper: drop the chain hash of the head row (as a DB-write attacker might).
    conn.execute("UPDATE audit_events SET row_hash = NULL WHERE seq = 3")
    conn.commit()

    init_sqlite_schema(conn)  # simulate a restart re-running migrations

    healed = conn.execute(
        "SELECT row_hash FROM audit_events WHERE seq = 3"
    ).fetchone()[0]
    assert healed is None, "post-migration NULL row_hash must not be re-chained"
    assert SQLiteAuditWriter(conn).verify_chain().ok is False


def test_seq_unique_index_rejects_duplicate_seq(tmp_path) -> None:
    conn, w = _writer(tmp_path)
    w.write(_event("evt_1"))
    w.write(_event("evt_2"))

    # A forked chain (two rows sharing a seq) is rejected by the unique index.
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE audit_events SET seq = 1 WHERE seq = 2")


def test_legacy_backfill_runs_once_then_seals(tmp_path) -> None:
    """A pre-hash-chain legacy DB still back-fills on first migration; once the
    sentinel is recorded, a later NULL is not re-healed."""
    conn = connect_sqlite(tmp_path / "legacy.sqlite")
    conn.executescript(
        "CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,"
        " decision TEXT NOT NULL, reason TEXT NOT NULL, workspace_id TEXT NOT NULL,"
        " agent_id TEXT NOT NULL, grant_id TEXT NOT NULL, grant_ref TEXT NOT NULL,"
        " action TEXT NOT NULL, resource TEXT NOT NULL, scope_attempted TEXT NOT NULL,"
        " scope_matched TEXT, boundary_id TEXT, runtime TEXT, boundary_type TEXT,"
        " created_at TEXT NOT NULL, event_json TEXT NOT NULL);"
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);"
    )
    _raw_event_row(conn, "evt_1", 1)
    _raw_event_row(conn, "evt_2", 2)

    init_sqlite_schema(conn)  # first migration: back-fill runs and seals (v14)

    assert 14 in get_sqlite_schema_versions(conn)
    assert SQLiteAuditWriter(conn).verify_chain().ok is True

    # Now sealed: a subsequent NULL is not re-chained on the next startup.
    conn.execute("UPDATE audit_events SET row_hash = NULL WHERE seq = 2")
    conn.commit()
    init_sqlite_schema(conn)
    assert (
        conn.execute("SELECT row_hash FROM audit_events WHERE seq = 2").fetchone()[0]
        is None
    )


def test_anchor_emission_deferred_to_outer_commit_and_dropped_on_rollback(
    tmp_path,
) -> None:
    """Codex P1: an audit write joined to an outer transaction must not emit its
    external anchor until the outermost commit, and must not emit it at all if
    that transaction rolls back (otherwise the anchor records a chain head that
    no longer exists)."""
    import vinctor_service.sqlite as sqlite_mod

    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    heads: list[int] = []

    class _RecordingAnchor:
        def emit(self, seq, row_hash, created_at):
            heads.append(seq)

        def emit_storage_op(self, *args, **kwargs):
            pass

    writer = SQLiteAuditWriter(conn, anchor=_RecordingAnchor())

    # Joined write that rolls back: the anchor is deferred, then discarded.
    with pytest.raises(RuntimeError), sqlite_mod._atomic_write(conn):
        writer.write(_event("evt_rollback"))
        assert heads == []  # deferred while the transaction is open
        raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0
    assert heads == []  # never emitted for the rolled-back row

    # Joined write that commits: the anchor emits exactly once, after commit.
    with sqlite_mod._atomic_write(conn):
        writer.write(_event("evt_commit"))
        assert heads == []  # still deferred inside the transaction
    assert heads == [1]


def test_manual_transaction_rollback_does_not_leak_deferred_emission(
    tmp_path,
) -> None:
    """Codex P1: emit_or_defer used to defer for ANY open transaction but only
    _atomic_write discarded on rollback, so an audit write in a caller-managed
    transaction that rolled back left a stale callback that flushed on the next
    _atomic_write. Deferral is now scoped to _atomic_write only: a manual
    transaction's audit write emits inline and never leaks into a later one."""
    import vinctor_service.sqlite as sqlite_mod

    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    heads: list[int] = []

    class _RecordingAnchor:
        def emit(self, seq, row_hash, created_at):
            heads.append(seq)

        def emit_storage_op(self, *args, **kwargs):
            pass

    writer = SQLiteAuditWriter(conn, anchor=_RecordingAnchor())

    # Caller-managed transaction, rolled back. The audit write is NOT inside an
    # _atomic_write, so it emits inline and queues no deferred callback.
    conn.execute("BEGIN")
    writer.write(_event("evt_manual"))
    conn.rollback()

    before = len(heads)
    # A later valid _atomic_write emits exactly ONE anchor (its own) — no stale
    # callback from the rolled-back manual transaction leaks in.
    with sqlite_mod._atomic_write(conn):
        writer.write(_event("evt_ok"))
    assert len(heads) - before == 1


def test_deferral_is_per_connection_not_per_thread(tmp_path) -> None:
    """Codex P1: the deferral was thread-scoped, so a standalone audit write on
    connection B made inside connection A's _atomic_write was queued in A's scope
    and DROPPED when A rolled back — losing the external anchor for B's committed
    row. Deferral is now per-connection, so B emits inline and survives."""
    import vinctor_service.sqlite as sqlite_mod

    conn_a = connect_sqlite(tmp_path / "a.sqlite")
    init_sqlite_schema(conn_a)
    conn_b = connect_sqlite(tmp_path / "b.sqlite")
    init_sqlite_schema(conn_b)
    heads_b: list[int] = []

    class _RecordingAnchor:
        def emit(self, seq, row_hash, created_at):
            heads_b.append(seq)

        def emit_storage_op(self, *args, **kwargs):
            pass

    writer_b = SQLiteAuditWriter(conn_b, anchor=_RecordingAnchor())

    # Inside connection A's _atomic_write (which rolls back), a STANDALONE audit
    # write on connection B commits independently on the same thread.
    with pytest.raises(RuntimeError), sqlite_mod._atomic_write(conn_a):
        writer_b.write(_event("evt_b"))
        raise RuntimeError("connection A rolls back")

    # B's row is committed and its anchor emitted exactly once — A's rollback did
    # NOT drop B's emission (it was never captured by A's scope).
    assert conn_b.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
    assert heads_b == [1]


# --- PKA-44: event_class column (schema v15) ------------------------------


def test_migration_adds_event_class_column_and_registers_v15(tmp_path) -> None:
    conn = connect_sqlite(tmp_path / "ec.sqlite")
    init_sqlite_schema(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert "event_class" in cols
    assert 15 in get_sqlite_schema_versions(conn)


def test_v14_rows_migrate_to_decision_class_and_still_verify(tmp_path) -> None:
    """Chain-affecting migration care: a v14-era DB (hash chain present, no
    event_class) migrates with every existing row reading as class "decision",
    and the chain still verifies — the stored event_json is untouched."""
    conn = connect_sqlite(tmp_path / "v14.sqlite")
    conn.executescript(
        "CREATE TABLE audit_events (event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,"
        " decision TEXT NOT NULL, reason TEXT NOT NULL, workspace_id TEXT NOT NULL,"
        " agent_id TEXT NOT NULL, grant_id TEXT NOT NULL, grant_ref TEXT NOT NULL,"
        " action TEXT NOT NULL, resource TEXT NOT NULL, scope_attempted TEXT NOT NULL,"
        " scope_matched TEXT, boundary_id TEXT, runtime TEXT, boundary_type TEXT,"
        " created_at TEXT NOT NULL, event_json TEXT NOT NULL,"
        " seq INTEGER, prev_hash TEXT, row_hash TEXT);"
        "CREATE UNIQUE INDEX idx_audit_events_seq ON audit_events(seq);"
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);"
    )
    for version in range(1, 15):
        conn.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (version, NOW.isoformat()),
        )
    prev = GENESIS_PREV_HASH
    for seq in (1, 2):
        ev = _event(f"evt_{seq}")
        ej = json.dumps(ev.to_dict(), sort_keys=True)
        rh = row_hash(seq, ej, prev)
        conn.execute(
            "INSERT INTO audit_events (event_id,event_type,decision,reason,workspace_id,"
            "agent_id,grant_id,grant_ref,action,resource,scope_attempted,scope_matched,"
            "boundary_id,runtime,boundary_type,created_at,event_json,seq,prev_hash,row_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"evt_{seq}", ev.event_type, ev.decision, ev.reason, ev.workspace_id,
             ev.agent_id, ev.grant_id, ev.grant_ref, ev.action, ev.resource,
             ev.scope_attempted, ev.scope_matched, ev.boundary_id, ev.runtime,
             ev.boundary_type, ev.created_at.isoformat(), ej, seq, prev, rh),
        )
        prev = rh
    conn.commit()

    init_sqlite_schema(conn)  # v14 -> v15: adds event_class

    assert 15 in get_sqlite_schema_versions(conn)
    classes = [r[0] for r in conn.execute(
        "SELECT event_class FROM audit_events ORDER BY seq").fetchall()]
    assert classes == ["decision", "decision"]
    w = SQLiteAuditWriter(conn)
    assert w.verify_chain().ok is True
    events = w.list_all()
    assert [e.event_class for e in events] == ["decision", "decision"]


def test_mixed_decision_and_control_chain_verifies(tmp_path) -> None:
    conn, w = _writer(tmp_path)
    w.write(_event("evt_1"))
    w.write(replace(_event("evt_2"), event_type="enforcement_setting_changed",
                    event_class="control"))
    w.write(_event("evt_3"))
    v = w.verify_chain()
    assert v.ok is True and v.count == 3
    assert [e.event_class for e in w.list_all()] == ["decision", "control", "decision"]


def test_verify_detects_event_class_column_tamper_on_control_row(tmp_path) -> None:
    # A DB-write attacker re-classifying a control event as an ordinary decision
    # (hiding it from per-category readers) without touching the hashed JSON must
    # break verification.
    conn, w = _writer(tmp_path)
    w.write(_event("evt_1"))
    w.write(replace(_event("evt_2"), event_type="enforcement_setting_changed",
                    event_class="control"))
    conn.execute("UPDATE audit_events SET event_class = 'decision' WHERE seq = 2")
    conn.commit()
    v = w.verify_chain()
    assert v.ok is False and v.break_kind == "column_mismatch" and v.break_seq == 2


def test_verify_detects_event_class_column_tamper_on_decision_row(tmp_path) -> None:
    conn, w = _seed_three(tmp_path)
    conn.execute("UPDATE audit_events SET event_class = 'control' WHERE seq = 2")
    conn.commit()
    v = w.verify_chain()
    assert v.ok is False and v.break_kind == "column_mismatch" and v.break_seq == 2
