from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from tempfile import TemporaryDirectory

from vinctor_core import BoundaryRegistrationInput, Grant, disable_boundary, register_boundary
from vinctor_service import (
    SQLiteAuditWriter,
    SQLiteBoundaryRegistry,
    SQLiteGrantRepository,
    V1EnforceRequest,
    enforce_v1_contract,
    init_sqlite_schema,
    insert_grant,
)
from vinctor_service.control_audit import ControlPlaneAuditor
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

        registry = SQLiteBoundaryRegistry(
            conn, ControlPlaneAuditor(SQLiteAuditWriter(conn))
        )
        boundary = register_boundary(
            registry,
            BoundaryRegistrationInput(
                workspace_id="ws_demo",
                name="claude-code-local",
                runtime="claude-code",
                boundary_type="pretooluse",
            ),
            now=now,
            boundary_id="bnd_demo",
        )

        permit = enforce_v1_contract(
            _request(boundary_id=boundary.boundary_id),
            grant_repository=SQLiteGrantRepository(conn),
            now=now,
            audit_writer=SQLiteAuditWriter(conn),
            boundary_registry=registry,
        )
        assert permit.status_code == 200
        assert _audit_boundary(conn, permit.audit_event_id or "") == (
            "bnd_demo",
            "claude-code",
            "pretooluse",
        )

        disable_boundary(
            registry,
            boundary_id=boundary.boundary_id,
            workspace_id="ws_demo",
            now=now + timedelta(seconds=1),
        )
        inactive = enforce_v1_contract(
            _request(boundary_id=boundary.boundary_id),
            grant_repository=SQLiteGrantRepository(conn),
            now=now,
            audit_writer=SQLiteAuditWriter(conn),
            boundary_registry=registry,
        )
        assert inactive.status_code == 403
        assert inactive.error == "boundary_unavailable"

        missing = enforce_v1_contract(
            _request(boundary_id="bnd_missing"),
            grant_repository=SQLiteGrantRepository(conn),
            now=now,
            audit_writer=SQLiteAuditWriter(conn),
            boundary_registry=registry,
        )
        assert missing.status_code == 403
        assert missing.error == "boundary_unavailable"
        assert _audit_boundary(conn, missing.audit_event_id or "") == (
            "bnd_missing",
            None,
            None,
        )

        conn.close()

    print("ALL SQLITE BOUNDARY REGISTRY STEPS PASSED \u2713")


def _request(*, boundary_id: str) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_demo",
        agent_id="agent_release",
        grant_ref="grt_demo",
        action="write",
        resource="repo/feature/readme",
        boundary_id=boundary_id,
    )


def _audit_boundary(
    conn: sqlite3.Connection,
    event_id: str,
) -> tuple[str | None, str | None, str | None]:
    row = conn.execute(
        "SELECT boundary_id, runtime, boundary_type FROM audit_events WHERE event_id = ?",
        (event_id,),
    ).fetchone()
    assert row is not None
    return row


if __name__ == "__main__":
    main()
