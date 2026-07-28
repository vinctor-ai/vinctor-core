from __future__ import annotations

from datetime import UTC, datetime

from vinctor_service import GrantRequestCreateRequest, InMemoryV1Service, V1EnforceRequest


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    service = InMemoryV1Service()
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_demo",
        agent_id="agent_runner",
        scopes=("write:repo/vinctor-core/*",),
        now=now,
    )

    created = service.create_grant_request(
        GrantRequestCreateRequest(
            workspace_id="ws_demo",
            requester_agent_id="agent_runner",
            requested_scopes=("write:repo/vinctor-core/README.md",),
            requested_ttl_seconds=1800,
            reason="update the core README",
            request_id="grq_manual_demo",
        ),
        now=now,
    )
    assert created.request is not None

    auto_attempt = service.auto_approve_grant_request(
        request_id=created.request.request_id,
        workspace_id="ws_demo",
        decided_by="workspace:ws_demo",
        now=now,
    )
    assert auto_attempt.status == "failed"
    assert auto_attempt.reason == "no_matching_rule"
    assert auto_attempt.request is not None
    assert auto_attempt.request.status == "pending"

    approved = service.approve_grant_request(
        request_id=created.request.request_id,
        workspace_id="ws_demo",
        decided_by="workspace:ws_demo",
        decision_reason="manual operator review",
        now=now,
    )
    assert approved.status == "approved"
    assert approved.grant is not None

    enforced = service.enforce(
        V1EnforceRequest(
            workspace_id="ws_demo",
            agent_id="agent_runner",
            grant_ref=approved.grant.grant_ref,
            action="write",
            resource="repo/vinctor-core/README.md",
        ),
        now=now,
    )
    assert enforced.decision == "permit"
    assert [event.event_type for event in service.audit_events] == [
        "grant_requested",
        "grant_issued",
        "grant_request_approved",
        "action_permitted",
    ]


if __name__ == "__main__":
    main()
