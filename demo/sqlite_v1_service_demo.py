from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from tempfile import TemporaryDirectory

from vinctor_core import BoundaryRegistrationInput, Grant
from vinctor_service import SQLiteV1Service, V1EnforceRequest


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    with TemporaryDirectory() as temp_dir:
        conn = sqlite3.connect(f"{temp_dir}/vinctor.sqlite")
        service = SQLiteV1Service(conn)
        service.insert_grant(
            Grant(
                grant_id="grnt_demo",
                grant_ref="grt_demo",
                workspace_id="ws_demo",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=now + timedelta(hours=1),
            )
        )
        boundary = service.register_boundary(
            BoundaryRegistrationInput(
                workspace_id="ws_demo",
                name="claude-code-local",
                runtime="claude-code",
                boundary_type="pretooluse",
            ),
            now=now,
            boundary_id="bnd_demo",
        )

        permit = service.enforce(_request(boundary_id=boundary.boundary_id), now=now)
        assert permit.status_code == 200
        assert permit.decision == "permit"
        assert _audit_count(conn) == 1

        deny = service.enforce(
            _request(action="send", resource="email/external", boundary_id=boundary.boundary_id),
            now=now,
        )
        assert deny.status_code == 403
        assert deny.error == "action_denied"
        assert _audit_count(conn) == 2

        missing_grant = service.enforce(
            _request(grant_ref="grt_missing", action="push", resource="repo"),
            now=now,
        )
        assert missing_grant.status_code == 403  # existence oracle: generic 403
        assert missing_grant.decision is None
        assert _audit_count(conn) == 2

        service.disable_boundary(
            boundary_id=boundary.boundary_id,
            workspace_id="ws_demo",
            now=now + timedelta(seconds=1),
        )
        inactive = service.enforce(_request(boundary_id=boundary.boundary_id), now=now)
        assert inactive.status_code == 403
        assert inactive.error == "boundary_inactive"
        assert _audit_count(conn) == 3

        conn.close()

    print("ALL SQLITE V1 SERVICE STEPS PASSED \u2713")


def _request(
    *,
    grant_ref: str = "grt_demo",
    action: str = "write",
    resource: str = "repo/feature/readme",
    boundary_id: str | None = None,
) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_demo",
        agent_id="agent_release",
        grant_ref=grant_ref,
        action=action,
        resource=resource,
        boundary_id=boundary_id,
    )


def _audit_count(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    return row[0]


if __name__ == "__main__":
    main()
