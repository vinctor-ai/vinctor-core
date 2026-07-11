from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_service import InMemoryV1Service, V1EnforceRequest


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    service = InMemoryV1Service(
        grants=(
            Grant(
                grant_id="grnt_core_repo",
                grant_ref="grt_core_repo",
                workspace_id="ws_demo",
                agent_id="agent_runner",
                scopes=("write:repo/vinctor-core/*",),
                status="active",
                expires_at=now + timedelta(hours=1),
            ),
        ),
    )

    core_write = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_demo",
            agent_id="agent_runner",
            grant_ref="grt_core_repo",
            action="write",
            resource="repo/vinctor-core/README.md",
        ),
        now=now,
    )
    sibling_write = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_demo",
            agent_id="agent_runner",
            grant_ref="grt_core_repo",
            action="write",
            resource="repo/vinctor-codex-hook/README.md",
        ),
        now=now,
    )

    assert core_write.decision == "permit"
    assert sibling_write.decision == "deny"
    assert "is not covered by grant" in sibling_write.reason
    assert [event.decision for event in service.audit_events] == ["permit", "deny"]


if __name__ == "__main__":
    main()
