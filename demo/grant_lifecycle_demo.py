from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_service import GrantIssueRequest, SQLiteV1Service, V1EnforceRequest
from vinctor_service.sqlite_txn import connect_sqlite


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    with tempfile.TemporaryDirectory() as temp_dir:
        conn = connect_sqlite(Path(temp_dir) / "vinctor.sqlite")
        try:
            service = SQLiteV1Service(conn)
            service.set_agent_issuable_scope_bounds(
                workspace_id="ws_demo",
                agent_id="agent_runner",
                scopes=("execute:ci/test", "execute:ci/build"),
                now=now,
            )

            issued = service.issue_grant(
                GrantIssueRequest(
                    workspace_id="ws_demo",
                    target_agent_id="agent_runner",
                    requested_scopes=("execute:ci/test",),
                    ttl_seconds=3600,
                    grant_id="grnt_demo",
                    grant_ref="grt_demo",
                ),
                now=now,
            )
            assert issued.status == "issued"
            assert issued.grant is not None
            assert issued.grant.expires_at == now + timedelta(seconds=3600)

            permit = service.enforce(
                V1EnforceRequest(
                    workspace_id="ws_demo",
                    agent_id="agent_runner",
                    grant_ref=issued.grant.grant_ref,
                    action="execute",
                    resource="ci/test",
                ),
                now=now,
            )
            assert permit.status_code == 200
            assert permit.decision == "permit"

            revoked = service.revoke_grant(
                grant_ref=issued.grant.grant_ref,
                workspace_id="ws_demo",
                now=now + timedelta(seconds=1),
            )
            assert revoked is not None

            denied = service.enforce(
                V1EnforceRequest(
                    workspace_id="ws_demo",
                    agent_id="agent_runner",
                    grant_ref=issued.grant.grant_ref,
                    action="execute",
                    resource="ci/test",
                ),
                now=now + timedelta(seconds=2),
            )
            assert denied.status_code == 403
            assert denied.error == "grant_revoked"
            assert [event.event_type for event in service.audit_events] == [
                "grant_issued",
                "action_permitted",
                "grant_revoked",
                "action_denied",
            ]
        finally:
            conn.close()

    print("ALL GRANT LIFECYCLE STEPS PASSED")


if __name__ == "__main__":
    main()
