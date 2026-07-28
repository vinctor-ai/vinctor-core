from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_core.audit import REASON_AGENT_GRANT_MISMATCH
from vinctor_service import (
    AgentIdentity,
    InMemoryV1Service,
    V1SimulateRequest,
    handle_v1_simulate_http,
)

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


def grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def test_simulate_records_would_permit_without_enforcing() -> None:
    service = InMemoryV1Service(grants=(grant(),))

    response = service.simulate(
        V1SimulateRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/feature/readme",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    assert response.would_decision == "permit"
    event = service.audit_events[0]
    assert response.audit_event_id == event.event_id
    assert event.event_type == "action_would_permit"
    assert event.decision == "permit"
    # No-disclosure: the matched scope is audit-only, never in the response.
    assert event.scope_matched == "write:repo/feature/*"


def test_simulate_records_would_deny_as_successful_dry_run() -> None:
    service = InMemoryV1Service(grants=(grant(),))

    response = service.simulate(
        V1SimulateRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_main",
            action="write",
            resource="repo/other/readme",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    assert response.would_decision == "deny"
    assert response.error == "action_denied"
    assert service.audit_events[0].event_type == "action_would_deny"
    assert service.audit_events[0].decision == "deny"


def test_simulate_unknown_grant_is_generic_would_deny_and_audited() -> None:
    service = InMemoryV1Service()

    response = service.simulate(
        V1SimulateRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref="grt_unknown",
            action="write",
            resource="repo/feature/readme",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    assert response.would_decision == "deny"
    assert response.error == "forbidden"
    assert "grt_unknown" not in (response.reason or "")
    event = service.audit_events[0]
    assert event.event_type == "action_would_deny"
    assert event.reason_code == REASON_AGENT_GRANT_MISMATCH
    assert event.grant_id == ""
    assert event.grant_ref == ""


def test_simulate_http_authenticates_and_returns_dry_run_result() -> None:
    service = InMemoryV1Service(grants=(grant(),))
    identities = {
        "agent_key_main": AgentIdentity(
            workspace_id="ws_main",
            agent_id="agent_release",
        )
    }

    response = handle_v1_simulate_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={
            "grant_ref": "grt_main",
            "action": "write",
            "resource": "repo/other/readme",
        },
        agent_identities=identities,
        service=service,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body["status"] == "simulated"
    assert response.body["would_decision"] == "deny"
    assert response.body["audit_event_id"] == service.audit_events[0].event_id


def test_simulate_http_rejects_raw_tool_input() -> None:
    service = InMemoryV1Service(grants=(grant(),))

    response = handle_v1_simulate_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={
            "grant_ref": "grt_main",
            "action": "write",
            "resource": "repo/feature/readme",
            "tool_input": "secret",
        },
        agent_identities={
            "agent_key_main": AgentIdentity(
                workspace_id="ws_main",
                agent_id="agent_release",
            )
        },
        service=service,
        now=NOW,
    )

    assert response.status_code == 400
    assert response.body["error"] == "invalid_request"
    assert service.audit_events == ()
