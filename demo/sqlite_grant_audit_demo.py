from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from tempfile import TemporaryDirectory

from vinctor_core import Grant
from vinctor_service import (
    SQLiteAuditWriter,
    SQLiteGrantRepository,
    V1EnforceRequest,
    enforce_v1_contract,
    init_sqlite_schema,
    insert_grant,
)
from vinctor_service.sqlite_txn import connect_sqlite


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)

    with TemporaryDirectory() as temp_dir:
        conn = connect_sqlite(f"{temp_dir}/vinctor.sqlite")
        init_sqlite_schema(conn)
        insert_grant(
            conn,
            Grant(
                grant_id="grnt_demo",
                grant_ref="grt_demo",
                workspace_id="ws_demo",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=now + timedelta(hours=1),
            ),
        )

        grant_repository = SQLiteGrantRepository(conn)
        audit_writer = SQLiteAuditWriter(conn)

        permit = enforce_v1_contract(
            V1EnforceRequest(
                workspace_id="ws_demo",
                agent_id="agent_release",
                grant_ref="grt_demo",
                action="write",
                resource="repo/feature/readme",
            ),
            grant_repository=grant_repository,
            now=now,
            audit_writer=audit_writer,
        )
        assert permit.status_code == 200
        assert permit.decision == "permit"
        assert _audit_count(conn) == 1

        deny = enforce_v1_contract(
            V1EnforceRequest(
                workspace_id="ws_demo",
                agent_id="agent_release",
                grant_ref="grt_demo",
                action="send",
                resource="email/external",
            ),
            grant_repository=grant_repository,
            now=now,
            audit_writer=audit_writer,
        )
        assert deny.status_code == 403
        assert deny.error == "action_denied"
        assert _audit_count(conn) == 2

        unknown = enforce_v1_contract(
            V1EnforceRequest(
                workspace_id="ws_demo",
                agent_id="agent_release",
                grant_ref="grt_missing",
                action="write",
                resource="repo/feature/readme",
            ),
            grant_repository=grant_repository,
            now=now,
            audit_writer=audit_writer,
        )
        assert unknown.status_code == 403  # existence oracle: generic 403
        assert unknown.decision is None
        # Timing oracle closed: unknown grant records the same coarse rejection a
        # foreign grant does, so this is the 3rd row (permit, deny, unknown).
        assert _audit_count(conn) == 3

        conn.close()

    print("ALL SQLITE GRANT/AUDIT STEPS PASSED \u2713")


def _audit_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    return row[0]


if __name__ == "__main__":
    main()
