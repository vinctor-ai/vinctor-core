# Audit hash-chain + anchoring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the SQLite audit log tamper-evident (a per-DB hash chain + `operator audit verify`) and, with an independent anchor sink, effectively tamper-resistant (continuous fail-open head emission + `verify --against-anchor`).

**Architecture:** Each `audit_events` row commits to its content and the prior row's hash (`row_hash = sha256(seq \n event_json \n prev_hash)`), computed inside the existing serialized `SQLiteAuditWriter.write` transaction and back-filled over existing rows by a schema migration. Read-only verify walks the chain and locates the first modify/delete/reorder/column-mismatch. A pluggable anchor emitter writes each committed head to a configured sink (file/stdout), off by default, async-safe/fail-open so it never blocks or denies enforce; `verify --against-anchor` checks the live chain against the recorded heads.

**Tech Stack:** Python 3.11, stdlib `hashlib`/`json`/`sqlite3`, existing `vinctor_service` SQLite layer, `pytest`, `ruff`.

**Repo:** `/Users/taeheon/dev/agent-authority/vinctor-core`. Branch `feat/audit-hash-chain` (spec already committed there). venv: `.venv/bin/python -m pytest`, `.venv/bin/ruff check`. main is human-merge-only — open a PR at the end, do NOT merge. Commit trailer ends with:
```
Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
```

---

## File Structure

- **Create** `src/vinctor_service/audit_chain.py` — pure chain primitive (`GENESIS_PREV_HASH`, `row_hash`) + result dataclasses (`ChainVerification`, `AnchorVerification`, `AnchorRecord`). No I/O.
- **Create** `src/vinctor_service/audit_anchor.py` — `AuditAnchor` protocol + `NullAnchor`, `FileAnchor`, `StdoutAnchor`, and `anchor_from_env(env)` factory. Fail-open head emission.
- **Modify** `src/vinctor_service/sqlite.py` — `_ensure_audit_events_hashchain_columns` + register migration v11 in `init_sqlite_schema`; back-fill; `SQLiteAuditWriter.__init__(conn, anchor=...)` + chain in `write`; `verify_chain`/`chain_head`/`verify_against_anchor` methods; wire anchor in `SQLiteV1Service.__post_init__`.
- **Modify** `src/vinctor_service/cli.py` — `operator audit head` + `operator audit verify` parsers + dispatch.
- **Modify** `README.md`, `docs/threat-model.md` — tamper-evidence + gradient table + commands.
- **Test** `tests/test_audit_chain.py`, `tests/test_audit_hash_chain_sqlite.py`, `tests/test_audit_anchor.py`, `tests/test_cli_audit_verify.py` (new); update any `grep`-all schema-version assertion.

---

## Task 1: Chain primitive + result types

**Files:**
- Create: `src/vinctor_service/audit_chain.py`
- Test: `tests/test_audit_chain.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_audit_chain.py
from vinctor_service.audit_chain import GENESIS_PREV_HASH, row_hash


def test_genesis_is_64_hex_zeros() -> None:
    assert GENESIS_PREV_HASH == "0" * 64


def test_row_hash_is_deterministic_and_sha256_hex() -> None:
    h1 = row_hash(1, '{"a":1}', GENESIS_PREV_HASH)
    h2 = row_hash(1, '{"a":1}', GENESIS_PREV_HASH)
    assert h1 == h2
    assert len(h1) == 64 and all(c in "0123456789abcdef" for c in h1)


def test_row_hash_changes_with_any_field() -> None:
    base = row_hash(1, '{"a":1}', GENESIS_PREV_HASH)
    assert row_hash(2, '{"a":1}', GENESIS_PREV_HASH) != base       # seq
    assert row_hash(1, '{"a":2}', GENESIS_PREV_HASH) != base       # content
    assert row_hash(1, '{"a":1}', "f" * 64) != base               # prev_hash
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit_chain.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'vinctor_service.audit_chain'`.

- [ ] **Step 3: Write minimal implementation**

```python
# src/vinctor_service/audit_chain.py
"""Tamper-evidence hash chain over the audit log (design:
docs/superpowers/specs/2026-07-12-audit-hash-chain-tamper-evidence-design.md).

Pure primitive + result types — no I/O. row_hash binds a row's sequence number,
its canonical event_json (json.dumps(..., sort_keys=True) — no literal newline,
so "\n" is a safe separator), and the previous row's hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

GENESIS_PREV_HASH = "0" * 64


def row_hash(seq: int, event_json: str, prev_hash: str) -> str:
    payload = f"{seq}\n{event_json}\n{prev_hash}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    count: int
    head_seq: int
    head_hash: str
    break_seq: int | None = None
    break_event_id: str | None = None
    break_kind: str | None = None  # modified | deleted | reordered | column_mismatch


@dataclass(frozen=True)
class AnchorRecord:
    seq: int
    row_hash: str


@dataclass(frozen=True)
class AnchorVerification:
    ok: bool
    checked: int
    covered_max_seq: int
    divergence_seq: int | None = None
    divergence_kind: str | None = None  # missing | mismatch
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_audit_chain.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/audit_chain.py tests/test_audit_chain.py
git commit -m "feat(audit): hash-chain primitive + result types

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Schema migration (v11) + back-fill

**Files:**
- Modify: `src/vinctor_service/sqlite.py` (add `_ensure_audit_events_hashchain_columns`; call it + register v11 inside `init_sqlite_schema`, near the existing `_ensure_*` calls around line 220-296)
- Test: `tests/test_audit_hash_chain_sqlite.py`

Reference: mirror `_ensure_agent_enforcement_require_pop_column` (sqlite.py:395). The back-fill uses `row_hash` from Task 1 over existing rows in `rowid` order.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_audit_hash_chain_sqlite.py
import json
import sqlite3
from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_core.models import AuditEvent
from vinctor_service.audit_chain import GENESIS_PREV_HASH, row_hash
from vinctor_service.sqlite import init_sqlite_schema, get_sqlite_schema_versions

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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -q`
Expected: FAIL — the `seq`/`prev_hash`/`row_hash` columns don't exist and v11 isn't registered.

- [ ] **Step 3: Write minimal implementation**

Add this function near the other `_ensure_*` helpers (after `_ensure_agent_enforcement_require_pop_column`, ~sqlite.py:405):

```python
def _ensure_audit_events_hashchain_columns(conn: sqlite3.Connection) -> None:
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
    }
    added = False
    if "seq" not in cols:
        conn.execute("ALTER TABLE audit_events ADD COLUMN seq INTEGER")
        added = True
    if "prev_hash" not in cols:
        conn.execute("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT")
        added = True
    if "row_hash" not in cols:
        conn.execute("ALTER TABLE audit_events ADD COLUMN row_hash TEXT")
        added = True
    # Back-fill any rows lacking chain metadata, in rowid (insertion) order.
    unchained = conn.execute(
        "SELECT rowid, event_json FROM audit_events WHERE row_hash IS NULL ORDER BY rowid"
    ).fetchall()
    if unchained:
        start_seq_row = conn.execute(
            "SELECT COALESCE(MAX(seq), 0), "
            "(SELECT row_hash FROM audit_events WHERE seq = (SELECT MAX(seq) "
            "FROM audit_events WHERE row_hash IS NOT NULL)) "
            "FROM audit_events WHERE row_hash IS NOT NULL"
        ).fetchone()
        seq = start_seq_row[0] or 0
        prev = start_seq_row[1] or GENESIS_PREV_HASH
        for rowid, event_json in unchained:
            seq += 1
            rh = row_hash(seq, event_json, prev)
            conn.execute(
                "UPDATE audit_events SET seq = ?, prev_hash = ?, row_hash = ? WHERE rowid = ?",
                (seq, prev, rh, rowid),
            )
            prev = rh
    if added or unchained:
        conn.commit()
```

Add `from vinctor_service.audit_chain import GENESIS_PREV_HASH, row_hash` to the imports at the top of `sqlite.py`. Inside `init_sqlite_schema`, after the `_ensure_agent_enforcement_require_pop_column(conn)` call (~line 227), add:

```python
    _ensure_audit_events_hashchain_columns(conn)
```

And after the existing `(10, ...)` migration-version `INSERT OR IGNORE` block, add the v11 record:

```python
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (11, datetime.now(UTC).isoformat()),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/sqlite.py tests/test_audit_hash_chain_sqlite.py
git commit -m "feat(audit): schema v11 hash-chain columns + back-fill

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Chain on append (`SQLiteAuditWriter.write`)

**Files:**
- Modify: `src/vinctor_service/sqlite.py` (`SQLiteAuditWriter.write`, sqlite.py:1053)
- Test: `tests/test_audit_hash_chain_sqlite.py` (append to the file from Task 2)

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_audit_hash_chain_sqlite.py
from vinctor_service.sqlite import SQLiteAuditWriter


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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py::test_write_assigns_gapless_seq_and_valid_chain -q`
Expected: FAIL — `seq`/`prev_hash`/`row_hash` are NULL (write doesn't set them yet); `rows[0][1] == GENESIS_PREV_HASH` fails.

- [ ] **Step 3: Write minimal implementation**

Replace the body of `SQLiteAuditWriter.write` (sqlite.py:1053) so it computes and stores the chain columns inside the same transaction, then emits the head (the emit line is a no-op until Task 7 injects a real anchor — add the `self._anchor` attribute defaulting to `NullAnchor()` now):

```python
    def write(self, event: AuditEvent) -> None:
        event_data = event.to_dict()
        event_json = json.dumps(event_data, sort_keys=True)
        with self._conn:
            head = self._conn.execute(
                "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_seq = head[0] if head else 0
            prev_hash = head[1] if head else GENESIS_PREV_HASH
            seq = prev_seq + 1
            rh = row_hash(seq, event_json, prev_hash)
            self._conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, event_type, decision, reason,
                    workspace_id, agent_id, grant_id, grant_ref,
                    action, resource, scope_attempted, scope_matched,
                    boundary_id, runtime, boundary_type, created_at, event_json,
                    seq, prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id, event.event_type, event.decision, event.reason,
                    event.workspace_id, event.agent_id, event.grant_id, event.grant_ref,
                    event.action, event.resource, event.scope_attempted,
                    event.scope_matched, event.boundary_id, event.runtime,
                    event.boundary_type, event.created_at.isoformat(), event_json,
                    seq, prev_hash, rh,
                ),
            )
        # Post-commit, outside the txn: emit the head to the anchor sink. Fail-open
        # (NullAnchor until an anchor is wired in Task 7).
        self._anchor.emit(seq, rh, event.created_at.isoformat())
```

Update `SQLiteAuditWriter.__init__` to hold a default no-op anchor (the real type arrives in Task 6/7):

```python
    def __init__(self, conn: sqlite3.Connection, anchor: "AuditAnchor | None" = None) -> None:
        self._conn = conn
        self._anchor = anchor if anchor is not None else NullAnchor()
```

Add this import at the top of `sqlite.py`: `from vinctor_service.audit_anchor import AuditAnchor, NullAnchor`.

> **Execution order:** run **Task 6 before Task 3** (Task 6 creates `audit_anchor.py`, which this import needs). The task numbers are a logical grouping, not a strict order — do `1 → 6 → 2 → 3 → 4 → 5 → 7 → 8 → 9 → 10`. Every task still ends green on its own once its dependencies exist.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/sqlite.py tests/test_audit_hash_chain_sqlite.py
git commit -m "feat(audit): chain each appended row in SQLiteAuditWriter.write

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `verify_chain` + tamper detection

**Files:**
- Modify: `src/vinctor_service/sqlite.py` (add `verify_chain` method to `SQLiteAuditWriter`)
- Test: `tests/test_audit_hash_chain_sqlite.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_audit_hash_chain_sqlite.py
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -k verify -q`
Expected: FAIL — `AttributeError: 'SQLiteAuditWriter' object has no attribute 'verify_chain'`.

- [ ] **Step 3: Write minimal implementation**

Add to `SQLiteAuditWriter` (columns cross-checked are the ones mirrored in `event_json` via `AuditEvent.to_dict`):

```python
    _CROSSCHECK_COLUMNS = (
        "event_id", "event_type", "decision", "reason", "workspace_id", "agent_id",
        "grant_id", "grant_ref", "action", "resource", "scope_attempted",
        "scope_matched", "boundary_id", "runtime", "boundary_type",
    )

    def verify_chain(self) -> ChainVerification:
        rows = self._conn.execute(
            "SELECT seq, prev_hash, row_hash, event_json, "
            + ", ".join(self._CROSSCHECK_COLUMNS)
            + " FROM audit_events ORDER BY seq"
        ).fetchall()
        prev = GENESIS_PREV_HASH
        expected_seq = 1
        head_seq, head_hash = 0, GENESIS_PREV_HASH
        for row in rows:
            seq, prev_hash, stored_hash, event_json = row[0], row[1], row[2], row[3]
            cols = row[4:]
            event_id = cols[0]
            if seq != expected_seq:
                return ChainVerification(
                    False, len(rows), head_seq, head_hash,
                    break_seq=expected_seq, break_event_id=event_id, break_kind="deleted",
                )
            if prev_hash != prev:
                return ChainVerification(
                    False, len(rows), head_seq, head_hash,
                    break_seq=seq, break_event_id=event_id, break_kind="reordered",
                )
            if stored_hash != row_hash(seq, event_json, prev_hash):
                return ChainVerification(
                    False, len(rows), head_seq, head_hash,
                    break_seq=seq, break_event_id=event_id, break_kind="modified",
                )
            data = json.loads(event_json)
            for name, value in zip(self._CROSSCHECK_COLUMNS, cols):
                if data.get(name) != value:
                    return ChainVerification(
                        False, len(rows), head_seq, head_hash,
                        break_seq=seq, break_event_id=event_id,
                        break_kind="column_mismatch",
                    )
            prev = stored_hash
            head_seq, head_hash = seq, stored_hash
            expected_seq += 1
        return ChainVerification(True, len(rows), head_seq, head_hash)
```

Add `from vinctor_service.audit_chain import ChainVerification` to the sqlite.py imports.

> Note on `column_mismatch` vs `modified` ordering: the hash check runs first, so editing `event_json` is `modified`; editing only a denormalized column (hash still valid) is `column_mismatch`. Both are covered by the two separate tests.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -k verify -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/sqlite.py tests/test_audit_hash_chain_sqlite.py
git commit -m "feat(audit): verify_chain detects modify/delete/reorder/column-tamper

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `chain_head` + `verify_against_anchor`

**Files:**
- Modify: `src/vinctor_service/sqlite.py` (add `chain_head`, `verify_against_anchor` to `SQLiteAuditWriter`)
- Test: `tests/test_audit_hash_chain_sqlite.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_audit_hash_chain_sqlite.py
from vinctor_service.audit_chain import AnchorRecord


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
    conn.execute("UPDATE audit_events SET event_json=?, row_hash=? WHERE seq=2", (forged, rh2))
    conn.execute("UPDATE audit_events SET prev_hash=?, row_hash=? WHERE seq=3", (rh2, rh3))
    conn.commit()
    assert w.verify_chain().ok is True                      # internally consistent now
    av = w.verify_against_anchor(anchors)                    # ...but the anchor disagrees
    assert av.ok is False and av.divergence_seq == 2 and av.divergence_kind == "mismatch"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -k "chain_head or against_anchor" -q`
Expected: FAIL — methods don't exist.

- [ ] **Step 3: Write minimal implementation**

```python
    def chain_head(self) -> tuple[int, str]:
        row = self._conn.execute(
            "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, GENESIS_PREV_HASH)

    def verify_against_anchor(self, records: "list[AnchorRecord]") -> AnchorVerification:
        # `records` MUST be a concrete sequence (list/tuple), not a generator, so
        # `len(records)` is correct after the loop.
        covered = 0
        for rec in records:
            row = self._conn.execute(
                "SELECT row_hash FROM audit_events WHERE seq = ?", (rec.seq,)
            ).fetchone()
            if row is None:
                return AnchorVerification(
                    False, covered, covered, divergence_seq=rec.seq, divergence_kind="missing"
                )
            if row[0] != rec.row_hash:
                return AnchorVerification(
                    False, covered, covered, divergence_seq=rec.seq, divergence_kind="mismatch"
                )
            covered = max(covered, rec.seq)
        return AnchorVerification(True, len(records), covered)
```

Extend the sqlite.py chain import to include the anchor types: `from vinctor_service.audit_chain import AnchorRecord, AnchorVerification, ChainVerification, GENESIS_PREV_HASH, row_hash`.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -k "chain_head or against_anchor" -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/sqlite.py tests/test_audit_hash_chain_sqlite.py
git commit -m "feat(audit): chain_head + verify_against_anchor (external checkpoint)

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Anchor emitter (file/stdout, fail-open) — **run before Task 3**

**Files:**
- Create: `src/vinctor_service/audit_anchor.py`
- Test: `tests/test_audit_anchor.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_audit_anchor.py
import json

from vinctor_service.audit_anchor import (
    NullAnchor, FileAnchor, anchor_from_env,
)


def test_null_anchor_is_noop() -> None:
    NullAnchor().emit(1, "a" * 64, "2026-07-12T00:00:00+00:00")  # does not raise


def test_file_anchor_appends_one_json_line_per_head(tmp_path) -> None:
    path = tmp_path / "anchor.log"
    a = FileAnchor(str(path))
    a.emit(1, "h1", "t1")
    a.emit(2, "h2", "t2")
    lines = path.read_text().splitlines()
    assert [json.loads(x) for x in lines] == [
        {"seq": 1, "row_hash": "h1", "created_at": "t1"},
        {"seq": 2, "row_hash": "h2", "created_at": "t2"},
    ]


def test_file_anchor_is_fail_open_on_write_error(tmp_path) -> None:
    # A directory path can't be opened as a file for appending → emit must NOT raise.
    a = FileAnchor(str(tmp_path))  # tmp_path is a directory
    a.emit(1, "h1", "t1")  # swallowed, no exception


def test_anchor_from_env_selects_sink() -> None:
    assert isinstance(anchor_from_env({}), NullAnchor)
    assert isinstance(anchor_from_env({"VINCTOR_AUDIT_ANCHOR": ""}), NullAnchor)
    assert isinstance(
        anchor_from_env({"VINCTOR_AUDIT_ANCHOR": "file:/tmp/x.log"}), FileAnchor
    )
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit_anchor.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Write minimal implementation**

```python
# src/vinctor_service/audit_anchor.py
"""Audit chain-head anchoring (design §Anchor emission).

Emits each committed audit head {seq, row_hash, created_at} to a configured sink.
FAIL-OPEN by contract: a sink error is swallowed (logged to stderr) and NEVER
propagates into the enforce/audit-write path. Off by default (NullAnchor). The
first slice ships file + stdout sinks; network sinks (needing true async) land
later behind this same `emit` interface.
"""

from __future__ import annotations

import json
import sys
from typing import Protocol


class AuditAnchor(Protocol):
    def emit(self, seq: int, row_hash: str, created_at: str) -> None: ...


def _line(seq: int, row_hash: str, created_at: str) -> str:
    return json.dumps(
        {"seq": seq, "row_hash": row_hash, "created_at": created_at}, sort_keys=True
    )


class NullAnchor:
    """Anchoring disabled: no external writes, byte-compatible with pre-chain behavior."""

    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        return None


class StdoutAnchor:
    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        try:
            sys.stdout.write(_line(seq, row_hash, created_at) + "\n")
            sys.stdout.flush()
        except Exception as exc:  # fail-open
            sys.stderr.write(f"vinctor: audit anchor emit failed (stdout): {exc}\n")


class FileAnchor:
    def __init__(self, path: str) -> None:
        self._path = path

    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(_line(seq, row_hash, created_at) + "\n")
        except Exception as exc:  # fail-open: a dead anchor must never break enforce
            sys.stderr.write(f"vinctor: audit anchor emit failed (file): {exc}\n")


def anchor_from_env(env: dict[str, str]) -> AuditAnchor:
    """VINCTOR_AUDIT_ANCHOR: '' / unset -> off; 'stdout'; 'file:/abs/path'."""
    spec = (env.get("VINCTOR_AUDIT_ANCHOR") or "").strip()
    if not spec:
        return NullAnchor()
    if spec == "stdout":
        return StdoutAnchor()
    if spec.startswith("file:"):
        return FileAnchor(spec[len("file:"):])
    sys.stderr.write(
        f"vinctor: unknown VINCTOR_AUDIT_ANCHOR '{spec}'; anchoring disabled\n"
    )
    return NullAnchor()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_audit_anchor.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/audit_anchor.py tests/test_audit_anchor.py
git commit -m "feat(audit): pluggable fail-open anchor emitter (file/stdout, off by default)

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Wire the anchor into the service + prove fail-open at the write layer

**Files:**
- Modify: `src/vinctor_service/sqlite.py` (`SQLiteV1Service.__post_init__`, sqlite.py:1251) — build the anchor from env and pass to `SQLiteAuditWriter`
- Test: `tests/test_audit_hash_chain_sqlite.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_audit_hash_chain_sqlite.py
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
    assert v.ok is True and v.count == 400 and v.head_seq == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -k "emits_head or fail_open" -q`
Expected: FAIL — `test_write_is_fail_open_when_anchor_raises` raises `RuntimeError` (the `emit` in Task 3 isn't yet guarded). (The concurrency test also passes once Task 3's chain lands — run it in Step 4.)

- [ ] **Step 3: Write minimal implementation**

Guard the emit call in `SQLiteAuditWriter.write` (the emit must be fail-open even though the FileAnchor/StdoutAnchor already swallow — a custom/foreign anchor might not):

```python
        # Post-commit head emission — fail-open: a raising anchor must never
        # surface into the enforce path or unwind the committed audit row.
        try:
            self._anchor.emit(seq, rh, event.created_at.isoformat())
        except Exception as exc:  # noqa: BLE001 - deliberate fail-open
            import sys
            sys.stderr.write(f"vinctor: audit anchor emit raised: {exc}\n")
```

Wire the anchor from env in `SQLiteV1Service.__post_init__` (sqlite.py:1251) — replace `self.audit_writer = SQLiteAuditWriter(self.conn)` with:

```python
        import os
        self.audit_writer = SQLiteAuditWriter(
            self.conn, anchor=anchor_from_env(dict(os.environ))
        )
```

Add `from vinctor_service.audit_anchor import anchor_from_env` to sqlite.py imports (alongside the `AuditAnchor, NullAnchor` import from Task 3).

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_audit_hash_chain_sqlite.py -q`
Expected: PASS — the anchor-emit + fail-open tests, the concurrency test, and every earlier chain test in the file.

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/sqlite.py tests/test_audit_hash_chain_sqlite.py
git commit -m "feat(audit): wire env-configured anchor into the service, guard emit fail-open

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: CLI `operator audit head`

**Files:**
- Modify: `src/vinctor_service/cli.py` (add the `head` subparser near the `audit` subcommands at cli.py:591; add dispatch near the `audit_command` handling at cli.py:1389)
- Test: `tests/test_cli_audit_verify.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_audit_verify.py
import json
import sqlite3
from datetime import UTC, datetime

import pytest

from vinctor_core.models import AuditEvent
from vinctor_service.cli import main
from vinctor_service.sqlite import SQLiteV1Service

NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _service_with_two_events(db_path: str) -> None:
    svc = SQLiteV1Service(sqlite3.connect(db_path))
    for i in (1, 2):
        svc.audit_writer.write(AuditEvent(
            event_id=f"evt_{i}", event_type="action_permitted", decision="permit",
            reason="ok", workspace_id="ws_main", agent_id="agent_a", grant_id="g",
            grant_ref="grt_1", action="read", resource="repo/x",
            scope_attempted="read:repo/x", scope_matched="read:repo/*",
            boundary_id=None, runtime=None, boundary_type=None, created_at=NOW))
    svc.conn.close()


def test_audit_head_json(tmp_path, capsys) -> None:
    # `main` raises SystemExit (it is annotated NoReturn) — never returns an rc.
    db = str(tmp_path / "v.sqlite")
    _service_with_two_events(db)
    with pytest.raises(SystemExit) as ex:
        main(["--db", db, "operator", "audit", "head", "-o", "json"])
    assert ex.value.code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["seq"] == 2 and len(out["row_hash"]) == 64
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_cli_audit_verify.py::test_audit_head_json -q`
Expected: FAIL — `unknown audit command: head` raised as `CliError`, `main` exits non-zero (`ex.value.code != 0`).

- [ ] **Step 3: Write minimal implementation**

Add the parser after the `audit_export` parser (cli.py:~625):

```python
    audit_commands.add_parser(
        "head",
        help="Print the current audit chain head (seq + row_hash) for anchoring.",
        description="Print the tip of the tamper-evidence hash chain. Record it "
        "out-of-band and pass it later to `verify --expected-head`.",
    )
```

Add a `head` branch at the **top** of `_operator_audit(args, *, stdout)` (cli.py:1388), before the existing `if args.audit_command == "export":` line. It mirrors the exact conventions the sibling branches use: `_sqlite_service(args.db)` for the service, `_emit(args, body, text, stdout=stdout)` for output (`args.output`/`args.json` are inherited common options — see `_emit`, which checks `args.json or args.output == "json"`):

```python
    if args.audit_command == "head":
        seq, row_hash = _sqlite_service(args.db).audit_writer.chain_head()
        _emit(
            args,
            {"seq": seq, "row_hash": row_hash},
            f"seq={seq} row_hash={row_hash}",
            stdout=stdout,
        )
        return
```

The `head`/`verify` subcommands are whole-DB integrity checks, so — like `audit list` and unlike `audit export` — they use `args.db` directly and need **no** workspace key.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli_audit_verify.py::test_audit_head_json -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/cli.py tests/test_cli_audit_verify.py
git commit -m "feat(cli): operator audit head

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 9: CLI `operator audit verify` (`--expected-head`, `--against-anchor`)

**Files:**
- Modify: `src/vinctor_service/cli.py`
- Test: `tests/test_cli_audit_verify.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_cli_audit_verify.py
def test_audit_verify_ok_then_detects_tamper(tmp_path, capsys) -> None:
    db = str(tmp_path / "v.sqlite")
    _service_with_two_events(db)
    with pytest.raises(SystemExit) as ex:
        main(["--db", db, "operator", "audit", "verify", "-o", "json"])
    assert ex.value.code == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True

    conn = sqlite3.connect(db)
    forged = json.dumps({"decision": "deny"}, sort_keys=True)
    conn.execute("UPDATE audit_events SET event_json = ? WHERE seq = 2", (forged,))
    conn.commit(); conn.close()

    with pytest.raises(SystemExit) as ex:
        main(["--db", db, "operator", "audit", "verify", "-o", "json"])
    assert ex.value.code != 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] is False and out["break_seq"] == 2 and out["break_kind"] == "modified"


def test_audit_verify_expected_head_mismatch(tmp_path, capsys) -> None:
    db = str(tmp_path / "v.sqlite")
    _service_with_two_events(db)
    with pytest.raises(SystemExit) as ex:
        main(["--db", db, "operator", "audit", "verify",
              "--expected-head", "deadbeef", "-o", "json"])
    assert ex.value.code != 0
    assert json.loads(capsys.readouterr().out)["ok"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/test_cli_audit_verify.py -k verify -q`
Expected: FAIL — `unknown audit command: verify`.

- [ ] **Step 3: Write minimal implementation**

Parser (after `head`):

```python
    audit_verify = audit_commands.add_parser(
        "verify",
        help="Verify the audit chain is untampered (tamper-evidence).",
        description="Walk the hash chain and report the first modify/delete/reorder/"
        "column-mismatch. Exit non-zero on any break.",
    )
    audit_verify.add_argument(
        "--expected-head",
        help="Fail if the live chain head hash differs from this value "
        "(catches truncation/rollback that is internally consistent).",
    )
    audit_verify.add_argument(
        "--against-anchor",
        help="Path to a head-log (JSON lines of {seq,row_hash}); '-' for stdin. "
        "Fail if the live chain diverges from any recorded head.",
    )
```

Dispatch — add a `verify` branch at the top of `_operator_audit`, next to the `head` branch (before the `export`/`list` logic). Emit the result JSON via `_emit`, then signal a broken chain by raising `CliError(..., code=EXIT_DENIED, quiet_json=True)` so `main` exits non-zero AFTER the JSON has already gone to stdout (`quiet_json` suppresses a second error payload on stdout; the message goes to stderr):

```python
    if args.audit_command == "verify":
        writer = _sqlite_service(args.db).audit_writer
        v = writer.verify_chain()
        result = {
            "ok": v.ok, "count": v.count, "head_seq": v.head_seq,
            "head_hash": v.head_hash, "break_seq": v.break_seq,
            "break_event_id": v.break_event_id, "break_kind": v.break_kind,
        }
        ok = v.ok
        if ok and args.expected_head is not None and v.head_hash != args.expected_head:
            ok = False
            result["ok"] = False
            result["expected_head_mismatch"] = True
        if ok and args.against_anchor is not None:
            raw = (
                sys.stdin.read()
                if args.against_anchor == "-"
                else Path(args.against_anchor).read_text(encoding="utf-8")
            )
            records = [
                AnchorRecord(seq=int(d["seq"]), row_hash=str(d["row_hash"]))
                for d in (json.loads(line) for line in raw.splitlines() if line.strip())
            ]
            av = writer.verify_against_anchor(records)
            result["anchor"] = {
                "ok": av.ok, "checked": av.checked,
                "covered_max_seq": av.covered_max_seq,
                "divergence_seq": av.divergence_seq,
                "divergence_kind": av.divergence_kind,
            }
            ok = ok and av.ok
        _emit(args, result, "audit chain OK" if ok else "audit chain BROKEN", stdout=stdout)
        if not ok:
            raise CliError(
                "audit chain verification failed", code=EXIT_DENIED, quiet_json=True
            )
        return
```

Add `from vinctor_service.audit_chain import AnchorRecord` to the cli.py imports. `sys`, `Path`, `json`, `_emit`, `CliError`, `EXIT_DENIED`, and `_sqlite_service` are already imported/defined in cli.py.

- [ ] **Step 4: Run test to verify it passes**

Run: `.venv/bin/python -m pytest tests/test_cli_audit_verify.py -k verify -q`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add src/vinctor_service/cli.py tests/test_cli_audit_verify.py
git commit -m "feat(cli): operator audit verify (--expected-head, --against-anchor)

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 10: Docs + full-suite + schema-version assertions

**Files:**
- Modify: `README.md` (Audit Semantics section), `docs/threat-model.md` (audit note)
- Verify: any test that greps schema versions

- [ ] **Step 1: Update the schema-version assertion (if present)**

Run: `grep -rn "schema_versions\|range(1, 1[01])\|== 10\|version.*10" tests/ | grep -i schema`
If a test asserts the set/max of `schema_versions()`, extend it to include `11`. Run that test file; expect PASS. (If none exists, skip — Task 2 already asserts `11 in get_sqlite_schema_versions`.)

- [ ] **Step 2: README — Audit Semantics**

In `README.md`, under the audit section, add:

```markdown
### Tamper-evidence

Every audit row is hash-chained (`seq` + `prev_hash` + `row_hash =
sha256(seq \n event_json \n prev_hash)`). `vinctor operator audit verify` walks
the chain and reports the first modification, deletion, reorder, or
filter-column edit. `vinctor operator audit head` prints the chain tip.

The chain makes tampering **detectable**; how far it is **preventable** depends
on where you anchor the head (`VINCTOR_AUDIT_ANCHOR=file:/secured/path` or
`stdout`):

| Anchor | Guarantee vs. an attacker who controls the DB file |
| --- | --- |
| none | tamper-evident (a surgical edit breaks the chain; a full-tail recompute is undetectable without a reference) |
| same-host, same-privilege file | still only evident — the attacker rewrites the anchor too |
| OS-separated local (append-only / root-owned / WORM) | resistant up to defeating that separation |
| independent external sink | effectively resistant; only the un-anchored tail is exposed |

Anchoring is off by default and fail-open (a dead sink never blocks or denies an
enforce). `vinctor operator audit verify --against-anchor <head-log>` checks the
live chain against the recorded heads. This is tamper-**evident**, not
tamper-**proof**; for a compliance system of record, forward audit to durable
WORM/SIEM storage.
```

- [ ] **Step 3: threat-model — audit note**

In `docs/threat-model.md`, replace the audit determinism note with:

```markdown
The audit log is a **tamper-evident** hash chain (`operator audit verify`). A
determined attacker who controls the SQLite file can recompute the whole tail
(unkeyed SHA-256), so local evidence alone is not prevention; anchoring the chain
head to an independent, append-only sink (`VINCTOR_AUDIT_ANCHOR`) closes that
residual up to the anchor cadence and the sink's independence. Cryptographic
signing and full-event SIEM streaming are future work.
```

- [ ] **Step 4: Run the full suite + ruff**

Run:
```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check src/vinctor_service/audit_chain.py src/vinctor_service/audit_anchor.py src/vinctor_service/sqlite.py src/vinctor_service/cli.py tests/test_audit_chain.py tests/test_audit_hash_chain_sqlite.py tests/test_audit_anchor.py tests/test_cli_audit_verify.py
```
Expected: all pass (≥ 610 prior + the new tests), ruff clean.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/threat-model.md tests/
git commit -m "docs(audit): tamper-evidence + anchoring gradient (README + threat-model)

Co-authored-by: heonminator <taeheon@lano.im>
Co-authored-by: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Final: open the PR

After all tasks green:

```bash
git push -u origin feat/audit-hash-chain
gh pr create --title "feat(audit): tamper-evident hash chain + anchoring" --body "<summary + spec link + test evidence + 🤖 Generated with Claude Code>"
```

Do NOT merge (main is human-merge-only).
