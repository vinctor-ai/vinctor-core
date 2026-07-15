from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_service import (
    AutoApprovalRule,
    GrantRequestCreateRequest,
    SQLiteV1Service,
    V1EnforceRequest,
)
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
                scopes=("execute:ci/test",),
                now=now,
            )
            service.create_auto_approval_rule(
                AutoApprovalRule(
                    rule_id="apr_ci",
                    workspace_id="ws_demo",
                    name="CI auto approval",
                    target_agent_id="agent_runner",
                    allowed_scopes=("execute:ci/*",),
                    max_ttl_seconds=3600,
                    status="active",
                    created_by="workspace:ws_demo",
                    created_at=now,
                )
            )
            created = service.create_grant_request(
                GrantRequestCreateRequest(
                    workspace_id="ws_demo",
                    requester_agent_id="agent_runner",
                    requested_scopes=("execute:ci/test",),
                    requested_ttl_seconds=1800,
                    reason="run CI validation for the current task",
                    request_id="grq_ci",
                ),
                now=now,
            )
            assert created.request is not None

            approved = service.auto_approve_grant_request(
                request_id=created.request.request_id,
                workspace_id="ws_demo",
                decided_by="workspace:ws_demo",
                now=now + timedelta(seconds=1),
            )
            assert approved.status == "approved"
            assert approved.auto_approval_rule_id == "apr_ci"
            assert approved.grant is not None

            permit = service.enforce(
                V1EnforceRequest(
                    workspace_id="ws_demo",
                    agent_id="agent_runner",
                    grant_ref=approved.grant.grant_ref,
                    action="execute",
                    resource="ci/test",
                ),
                now=now + timedelta(seconds=2),
            )
            assert permit.status_code == 200
            assert [event.event_type for event in service.audit_events] == [
                "grant_requested",
                "grant_issued",
                "grant_request_auto_approved",
                "action_permitted",
            ]
        finally:
            conn.close()

    print("ALL AUTO-APPROVAL SERVICE PATH STEPS PASSED")


if __name__ == "__main__":
    main()
