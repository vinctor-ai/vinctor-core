from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path

from vinctor_service import (
    AutoApprovalRule,
    GrantRequestCreateRequest,
    SQLiteV1Service,
)
from vinctor_service.sqlite_txn import connect_sqlite


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    with tempfile.TemporaryDirectory() as temp_dir:
        conn = connect_sqlite(Path(temp_dir) / "vinctor.sqlite")
        try:
            service = SQLiteV1Service(conn)
            service.create_auto_approval_rule(
                AutoApprovalRule(
                    rule_id="apr_ci",
                    workspace_id="ws_demo",
                    name="CI dry-run approval",
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

            evaluation = service.evaluate_auto_approval(request=created.request)

            assert evaluation.decision == "would_approve"
            assert evaluation.reason == "auto_approval_match"
            assert evaluation.rule is not None
            assert evaluation.rule.rule_id == "apr_ci"
            assert service.lookup_grant_request(
                request_id="grq_ci",
                workspace_id="ws_demo",
            ).status == "pending"
            assert [event.event_type for event in service.audit_events] == [
                "grant_requested",
            ]
        finally:
            conn.close()

    print("ALL AUTO-APPROVAL DRY-RUN STEPS PASSED")


if __name__ == "__main__":
    main()
