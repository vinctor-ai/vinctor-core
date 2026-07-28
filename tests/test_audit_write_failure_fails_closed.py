"""An audit write that fails must take the decision down with it (PKA-181).

The README states this as a **property**, not as something an operator turns
on, so these tests pin the wire-level shape a PEP actually sees. The audit-write
failure is injected at the storage layer with a `RAISE(ABORT)` trigger on
`audit_events`, which is the only way to exercise the branch without stubbing
out the writer the branch exists to protect.

Each case carries a positive control: the same call on the same database
without the trigger returns its real permit/deny decision. Without that, a test that
stopped reaching the enforce path at all — bad grant_ref, wrong workspace,
schema drift — would still see "no decision in the body" and pass.
"""
from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service import AgentIdentity, SQLiteV1Service, handle_v1_enforce_http
from vinctor_service.models import GrantIssueRequest
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
AGENT_KEY = "agent_key_main"


def _seed(db_path: Path) -> sqlite3.Connection:
    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        now=NOW,
    )
    service.issue_grant(
        GrantIssueRequest(
            workspace_id="ws_main",
            target_agent_id="agent_release",
            requested_scopes=("write:repo/feature/*",),
            ttl_seconds=3600,
            grant_ref="grt_main",
        ),
        now=NOW,
    )
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws_main",
        agent_id="agent_release",
        require_boundary=False,
        now=NOW,
    )
    return conn


def _break_audit_writes(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TRIGGER fail_audit_write BEFORE INSERT ON audit_events "
        "BEGIN SELECT RAISE(ABORT, 'forced audit write failure'); END"
    )
    conn.commit()


def _enforce(conn: sqlite3.Connection, *, action: str, resource: str):
    return handle_v1_enforce_http(
        headers={"X-Agent-Key": AGENT_KEY},
        body={"grant_ref": "grt_main", "action": action, "resource": resource},
        agent_identities={
            AGENT_KEY: AgentIdentity(workspace_id="ws_main", agent_id="agent_release")
        },
        service=SQLiteV1Service(conn, initialize_schema=False),
        now=NOW,
    )


def _audit_row_count(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]


@pytest.mark.parametrize(
    ("action", "resource", "healthy_status", "expected_decision"),
    [
        ("write", "repo/feature/readme", 200, "permit"),
        ("write", "repo/main/readme", 403, "deny"),
        ("delete", "repo/feature/readme", 403, "deny"),
    ],
)
def test_audit_write_failure_returns_503_with_no_decision_field(
    tmp_path: Path,
    action: str,
    resource: str,
    healthy_status: int,
    expected_decision: str,
) -> None:
    conn = _seed(tmp_path / "vinctor.sqlite")
    try:
        # Positive control: this exact call really does reach a decision, so the
        # 503 below is the audit failure and not a broken setup.
        rows_seeded = _audit_row_count(conn)
        healthy = _enforce(conn, action=action, resource=resource)
        assert healthy.status_code == healthy_status
        assert healthy.body["decision"] == expected_decision
        rows_before = _audit_row_count(conn)
        assert rows_before == rows_seeded + 1

        _break_audit_writes(conn)
        response = _enforce(conn, action=action, resource=resource)

        assert response.status_code == 503
        assert response.body == {
            "error": "service_unavailable",
            "reason": "audit write failed; no decision was recorded",
        }
        # A PEP must not be able to read this as a permit: there is no
        # `decision` key at all, on any of the three cases.
        assert "decision" not in response.body
        # No partial write and no forked chain: the failed attempt left the
        # chain exactly where the healthy call did.
        assert _audit_row_count(conn) == rows_before
        assert SQLiteV1Service(conn, initialize_schema=False).audit_writer.verify_chain().ok
    finally:
        conn.close()
