from __future__ import annotations

from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_service import AgentIdentity, InMemoryV1Service, handle_v1_enforce_http


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    service = InMemoryV1Service(
        grants=(
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
    )
    identities = {
        "agent_key_demo": AgentIdentity(
            workspace_id="ws_demo",
            agent_id="agent_release",
        )
    }

    permit = handle_v1_enforce_http(
        headers={"X-Agent-Key": "agent_key_demo"},
        body={
            "grant_ref": "grt_demo",
            "action": "write",
            "resource": "repo/feature/readme",
        },
        agent_identities=identities,
        service=service,
        now=now,
    )
    assert permit.status_code == 200
    assert permit.body["decision"] == "permit"

    strict_body = handle_v1_enforce_http(
        headers={"X-Agent-Key": "agent_key_demo"},
        body={
            "grant_ref": "grt_demo",
            "action": "write",
            "resource": "repo/feature/readme",
            "boundary_id": "bnd_not_allowed_in_body",
        },
        agent_identities=identities,
        service=service,
        now=now,
    )
    assert strict_body.status_code == 400
    assert strict_body.body["error"] == "invalid_request"

    missing_grant = handle_v1_enforce_http(
        headers={"X-Agent-Key": "agent_key_demo"},
        body={
            "grant_ref": "grt_missing",
            "action": "write",
            "resource": "repo/feature/readme",
        },
        agent_identities=identities,
        service=service,
        now=now,
    )
    assert missing_grant.status_code == 403  # existence oracle: generic 403
    assert missing_grant.body["error"] == "forbidden"  # existence oracle: generic 403

    assert len(service.audit_events) == 1
    print("ALL V1 HTTP CONTRACT STEPS PASSED \u2713")


if __name__ == "__main__":
    main()
