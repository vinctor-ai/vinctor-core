import json
from datetime import UTC, datetime
from io import StringIO

from vinctor_core.models import AuditEvent
from vinctor_service.cli import run_vinctor
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 7, 12, 12, 0, tzinfo=UTC)


def _service_with_two_events(db_path: str) -> None:
    svc = SQLiteV1Service(connect_sqlite(db_path))
    for i in (1, 2):
        svc.audit_writer.write(AuditEvent(
            event_id=f"evt_{i}", event_type="action_permitted", decision="permit",
            reason="ok", workspace_id="ws_main", agent_id="agent_a", grant_id="g",
            grant_ref="grt_1", action="read", resource="repo/x",
            scope_attempted="read:repo/x", scope_matched="read:repo/*",
            boundary_id=None, runtime=None, boundary_type=None, created_at=NOW))
    svc.conn.close()


def _run(argv: list[str]) -> tuple[int, str]:
    # run_vinctor binds its default stdout=sys.stdout at import time, which the
    # capsys fixture cannot observe; pass explicit streams (the proven test_cli.py
    # pattern) and use the returned status code instead of SystemExit.
    stdout, stderr = StringIO(), StringIO()
    status = run_vinctor(argv, stdout=stdout, stderr=stderr)
    return status, stdout.getvalue()


def test_audit_head_json(tmp_path) -> None:
    db = str(tmp_path / "v.sqlite")
    _service_with_two_events(db)
    status, out = _run(["--db", db, "operator", "audit", "head", "-o", "json"])
    assert status == 0
    parsed = json.loads(out)
    assert parsed["seq"] == 2 and len(parsed["row_hash"]) == 64


def test_audit_verify_ok_then_detects_tamper(tmp_path) -> None:
    db = str(tmp_path / "v.sqlite")
    _service_with_two_events(db)
    status, out = _run(["--db", db, "operator", "audit", "verify", "-o", "json"])
    assert status == 0
    assert json.loads(out)["ok"] is True

    conn = connect_sqlite(db)
    forged = json.dumps({"decision": "deny"}, sort_keys=True)
    conn.execute("UPDATE audit_events SET event_json = ? WHERE seq = 2", (forged,))
    conn.commit()
    conn.close()

    status, out = _run(["--db", db, "operator", "audit", "verify", "-o", "json"])
    assert status != 0
    parsed = json.loads(out)
    assert parsed["ok"] is False and parsed["break_seq"] == 2 and parsed["break_kind"] == "modified"


def test_audit_verify_expected_head_mismatch(tmp_path) -> None:
    db = str(tmp_path / "v.sqlite")
    _service_with_two_events(db)
    status, out = _run(
        ["--db", db, "operator", "audit", "verify", "--expected-head", "deadbeef", "-o", "json"]
    )
    assert status != 0
    assert json.loads(out)["ok"] is False
