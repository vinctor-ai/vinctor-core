"""Anchor coverage must reach the chain head (PKA-225).

`verify_against_anchor` used to walk only the records present in the anchor log
and report `ok` no matter how far short of the head they stopped. Anchor
emission is fail-open by contract (`audit_anchor`), so an attacker who makes the
sink unwritable gets an unbounded unanchored window — rows keep being written,
nothing is anchored — and can then rewrite that tail so `verify_chain` still
passes. `covered_max_seq` was computed and printed but compared to nothing.

The CLI half matters as much: `result["ok"]` used to stay true while
`result["anchor"]["ok"]` was false, so a consumer parsing `.ok` read a forged
chain as healthy even though the exit code was already 3.

Every identifier below is a decoy fixture.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path

from vinctor_core.models import AuditEvent
from vinctor_service.audit_anchor import FileAnchor
from vinctor_service.audit_chain import AnchorRecord, row_hash
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
EXIT_DENIED = 3


def _event(n: int) -> AuditEvent:
    return AuditEvent(
        event_id=f"evt_{n}", event_type="action_permitted", decision="permit",
        reason="ok", workspace_id="ws_decoy", agent_id="agent_decoy",
        grant_id="grnt_decoy", grant_ref="grt_decoy", action="read",
        resource="repo/x", scope_attempted="read:repo/x", scope_matched="read:repo/*",
        boundary_id="bnd_decoy", runtime="claude-code", boundary_type="pretooluse",
        created_at=NOW + timedelta(seconds=n),
    )


def _writer(tmp_path: Path, name: str = "a.sqlite"):
    conn = connect_sqlite(tmp_path / name)
    init_sqlite_schema(conn)
    return conn, SQLiteAuditWriter(conn)


def _anchors(conn, seqs) -> list[AnchorRecord]:
    return [
        AnchorRecord(
            seq=s,
            row_hash=conn.execute(
                "SELECT row_hash FROM audit_events WHERE seq = ?", (s,)
            ).fetchone()[0],
        )
        for s in seqs
    ]


def _run_cli(argv: list[str]) -> tuple[int, str]:
    from vinctor_service.cli import run_vinctor

    stdout, stderr = StringIO(), StringIO()
    status = run_vinctor(argv, stdout=stdout, stderr=stderr)
    return status, stdout.getvalue()


# --- verify_against_anchor ---------------------------------------------------


def test_full_coverage_still_verifies(tmp_path) -> None:
    conn, w = _writer(tmp_path)
    for n in (1, 2, 3):
        w.write(_event(n))
    av = w.verify_against_anchor(_anchors(conn, (1, 2, 3)))
    assert av.ok is True
    assert (av.checked, av.covered_max_seq, av.head_seq) == (3, 3, 3)
    assert av.divergence_kind is None


def test_coverage_short_of_head_fails_and_names_the_uncovered_range(tmp_path) -> None:
    conn, w = _writer(tmp_path)
    for n in range(1, 10):
        w.write(_event(n))

    # The anchor only ever saw seq 1..4 — the sink went away after that.
    av = w.verify_against_anchor(_anchors(conn, (1, 2, 3, 4)))

    assert av.ok is False
    assert av.divergence_kind == "uncovered"
    assert av.covered_max_seq == 4
    assert av.head_seq == 9
    # The first unanchored row, so the uncovered range is 5..9.
    assert av.divergence_seq == 5


def test_empty_anchor_against_a_populated_chain_fails(tmp_path) -> None:
    _conn, w = _writer(tmp_path)
    w.write(_event(1))
    av = w.verify_against_anchor([])
    assert av.ok is False and av.divergence_kind == "uncovered"
    assert (av.covered_max_seq, av.head_seq, av.divergence_seq) == (0, 1, 1)


def test_empty_anchor_against_an_empty_chain_is_ok(tmp_path) -> None:
    _conn, w = _writer(tmp_path)
    av = w.verify_against_anchor([])
    assert av.ok is True and av.head_seq == 0 and av.divergence_kind is None


def test_anchor_records_past_the_head_are_still_missing_not_uncovered(tmp_path) -> None:
    # A truncated chain must keep reporting the row the anchor asserts and the
    # database cannot produce, rather than being reclassified as coverage.
    conn, w = _writer(tmp_path)
    for n in (1, 2):
        w.write(_event(n))
    anchors = _anchors(conn, (1, 2)) + [AnchorRecord(seq=3, row_hash="f" * 64)]
    av = w.verify_against_anchor(anchors)
    assert av.ok is False and av.divergence_kind == "missing" and av.divergence_seq == 3


# --- CLI ---------------------------------------------------------------------


def test_cli_rejects_a_rewritten_tail_behind_a_suppressed_anchor(tmp_path) -> None:
    """The reported scenario, end to end.

    Four events are anchored, the sink is made unwritable (anchor emission is
    fail-open, so enforce keeps succeeding), five more events are written
    unanchored, then the unanchored tail is rewritten and one row dropped —
    re-chained so `verify_chain` alone passes.
    """
    db = tmp_path / "suppress.sqlite"
    anchor_path = tmp_path / "suppress.log"
    conn = connect_sqlite(db)
    init_sqlite_schema(conn)
    writer = SQLiteAuditWriter(conn, anchor=FileAnchor(str(anchor_path)))

    for n in range(1, 5):
        writer.write(_event(n))
    anchor_path.chmod(0o444)  # the sink is suppressed; emission fails fail-open
    for n in range(5, 10):
        writer.write(_event(n))

    assert conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 9
    assert len(anchor_path.read_text().splitlines()) == 4

    # Rewrite the unanchored window: drop seq 7, renumber and re-chain 5..8.
    tail = conn.execute(
        "SELECT seq, event_json FROM audit_events WHERE seq >= 5 ORDER BY seq"
    ).fetchall()
    kept = [ej for seq, ej in tail if seq != 7]
    conn.execute("DELETE FROM audit_events WHERE seq >= 5")
    prev = conn.execute("SELECT row_hash FROM audit_events WHERE seq = 4").fetchone()[0]
    for offset, event_json in enumerate(kept):
        seq = 5 + offset
        current = row_hash(seq, event_json, prev)
        data = json.loads(event_json)
        conn.execute(
            "INSERT INTO audit_events (event_id,event_type,decision,reason,workspace_id,"
            "agent_id,grant_id,grant_ref,action,resource,scope_attempted,scope_matched,"
            "boundary_id,runtime,boundary_type,created_at,event_json,seq,prev_hash,row_hash)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (data["event_id"], data["event_type"], data["decision"], data["reason"],
             data["workspace_id"], data["agent_id"], data["grant_id"], data["grant_ref"],
             data["action"], data["resource"], data["scope_attempted"],
             data["scope_matched"], data["boundary_id"], data["runtime"],
             data["boundary_type"], data["created_at"], event_json, seq, prev, current),
        )
        prev = current
    conn.commit()
    # The forged tail is internally consistent, which is exactly why the anchor
    # is the only thing that can catch it.
    assert SQLiteAuditWriter(conn, anchor=None).verify_chain().ok is True
    conn.close()

    status, out = _run_cli(
        ["--db", str(db), "operator", "audit", "verify",
         "--against-anchor", str(anchor_path), "-o", "json"]
    )

    parsed = json.loads(out)
    assert status == EXIT_DENIED
    assert parsed["ok"] is False
    assert parsed["anchor"]["ok"] is False
    assert parsed["anchor"]["divergence_kind"] == "uncovered"
    assert parsed["anchor"]["covered_max_seq"] == 4
    assert parsed["anchor"]["head_seq"] == 8
    assert parsed["anchor"]["divergence_seq"] == 5


def test_cli_top_level_ok_follows_the_anchor_verdict(tmp_path) -> None:
    # Independent of the coverage rule: a divergence INSIDE the covered window
    # must also flip the top-level `ok`, which is what a consumer parses.
    db = tmp_path / "mismatch.sqlite"
    conn = connect_sqlite(db)
    init_sqlite_schema(conn)
    writer = SQLiteAuditWriter(conn)
    for n in (1, 2):
        writer.write(_event(n))
    real = _anchors(conn, (1, 2))
    conn.close()

    anchor_path = tmp_path / "anchor.log"
    anchor_path.write_text(
        json.dumps({"seq": 1, "row_hash": real[0].row_hash, "created_at": "t"}) + "\n"
        + json.dumps({"seq": 2, "row_hash": "d" * 64, "created_at": "t"}) + "\n",
        encoding="utf-8",
    )

    status, out = _run_cli(
        ["--db", str(db), "operator", "audit", "verify",
         "--against-anchor", str(anchor_path), "-o", "json"]
    )

    parsed = json.loads(out)
    assert status == EXIT_DENIED
    assert parsed["ok"] is False
    assert parsed["anchor"]["ok"] is False
    assert parsed["anchor"]["divergence_kind"] == "mismatch"


def test_cli_accepts_a_fully_covered_chain(tmp_path) -> None:
    # Positive control: the fix must not turn a healthy anchored chain into a
    # failure, or the test above would pass for the wrong reason.
    db = tmp_path / "healthy.sqlite"
    anchor_path = tmp_path / "anchor.log"
    conn = connect_sqlite(db)
    init_sqlite_schema(conn)
    writer = SQLiteAuditWriter(conn, anchor=FileAnchor(str(anchor_path)))
    for n in (1, 2, 3):
        writer.write(_event(n))
    conn.close()

    status, out = _run_cli(
        ["--db", str(db), "operator", "audit", "verify",
         "--against-anchor", str(anchor_path), "-o", "json"]
    )

    parsed = json.loads(out)
    assert status == 0
    assert parsed["ok"] is True and parsed["anchor"]["ok"] is True
    assert parsed["anchor"]["covered_max_seq"] == parsed["head_seq"] == 3
