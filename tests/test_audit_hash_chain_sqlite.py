import json
import sqlite3
from datetime import UTC, datetime, timedelta

from vinctor_core.models import AuditEvent
from vinctor_service.audit_chain import GENESIS_PREV_HASH, AnchorRecord, row_hash
from vinctor_service.sqlite import (
    SQLiteAuditWriter,
    get_sqlite_schema_versions,
    init_sqlite_schema,
)

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
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(audit_events)").fetchall()}
    assert {"seq", "prev_hash", "row_hash"} <= cols
    assert 11 in get_sqlite_schema_versions(conn)


def test_backfill_chains_existing_rows_from_genesis(tmp_path) -> None:
    # Simulate a legacy DB: create the schema WITHOUT chain columns, insert rows,
    # then re-run init_sqlite_schema to migrate + back-fill.
    conn = sqlite3.connect(tmp_path / "legacy.sqlite")
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
    conn = sqlite3.connect(tmp_path / "w.sqlite")
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
    conn = sqlite3.connect(tmp_path / "a.sqlite")
    init_sqlite_schema(conn)
    emitted = []

    class _CaptureAnchor:
        def emit(self, seq, row_hash, created_at):
            emitted.append((seq, row_hash))

    w = SQLiteAuditWriter(conn, anchor=_CaptureAnchor())
    w.write(_event("evt_1"))
    assert len(emitted) == 1 and emitted[0][0] == 1


def test_write_is_fail_open_when_anchor_raises(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "b.sqlite")
    init_sqlite_schema(conn)

    class _BoomAnchor:
        def emit(self, seq, row_hash, created_at):
            raise RuntimeError("sink down")

    w = SQLiteAuditWriter(conn, anchor=_BoomAnchor())
    w.write(_event("evt_1"))  # must NOT raise
    # The row is still written + chained despite the anchor failure.
    assert w.verify_chain().ok is True and w.chain_head()[0] == 1


def test_chain_stays_valid_under_concurrent_enforce(tmp_path) -> None:
    # The chain's head-read-then-insert is safe because the local HTTP service
    # serializes DB-touching request handling with db_access_lock (2026-07-12
    # concurrency fix). Hammer a real service, then verify the resulting chain is
    # gapless and unbroken. Mirrors tests/test_local_http_concurrency.py.
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

    conn = sqlite3.connect(db_path)
    v = SQLiteAuditWriter(conn).verify_chain()
    # 401 = the 1 `grant_issued` event that prepare_local_service writes while
    # bootstrapping the local grant, plus the 400 concurrent enforce events. The
    # invariant under test is that the chain is valid and gapless (count == head_seq)
    # despite concurrency, not the exact bootstrap count.
    assert v.ok is True and v.count == 401 and v.head_seq == 401


def test_postgres_crosscheck_columns_match_sqlite() -> None:
    # Both backends MUST cross-check the same materialized columns against
    # event_json during verify_chain, or one backend would miss a tampering the
    # other catches. Guards drift without needing a live Postgres.
    from vinctor_service.postgres import PostgresAuditWriter

    assert PostgresAuditWriter._CROSSCHECK_COLUMNS == SQLiteAuditWriter._CROSSCHECK_COLUMNS
