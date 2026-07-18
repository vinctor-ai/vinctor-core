from datetime import UTC, datetime

from vinctor_service import (
    AgentIdentity,
    InMemoryV1Service,
    V1ObserveRequest,
    handle_v1_observe_http,
)

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)


def test_mapped_observation_is_audited_without_a_grant() -> None:
    service = InMemoryV1Service()

    response = service.observe(
        V1ObserveRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            classification="mapped",
            action="write",
            resource="repo/feature/readme",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    event = service.audit_events[0]
    assert response.audit_event_id == event.event_id
    assert event.event_type == "action_observed"
    assert event.decision == "permit"
    assert event.reason == "observe_mode"
    assert event.scope_attempted == "write:repo/feature/readme"
    assert event.grant_id == ""
    assert event.grant_ref == ""


def test_unmapped_observation_records_no_raw_tool_input() -> None:
    service = InMemoryV1Service()

    response = service.observe(
        V1ObserveRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            classification="unmapped",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    event = service.audit_events[0]
    assert event.event_type == "action_unmapped"
    assert event.action == ""
    assert event.resource == ""
    assert event.scope_attempted == ""


def test_blocked_unmapped_observation_records_coarse_deny() -> None:
    service = InMemoryV1Service()

    response = service.observe(
        V1ObserveRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            classification="unmapped",
            outcome="blocked_unmapped",
        ),
        now=NOW,
    )

    assert response.status_code == 200
    event = service.audit_events[0]
    assert event.event_type == "action_blocked_unmapped"
    assert event.decision == "deny"
    assert event.reason == "blocked_unmapped"
    assert event.action == ""
    assert event.resource == ""
    assert event.scope_attempted == ""
    assert response.audit_event_id == event.event_id


def test_observe_http_authenticates_agent_and_keeps_body_strict() -> None:
    service = InMemoryV1Service()
    identities = {
        "agent_key_main": AgentIdentity(
            workspace_id="ws_main",
            agent_id="agent_release",
        )
    }

    response = handle_v1_observe_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={
            "classification": "mapped",
            "action": "read",
            "resource": "repo/feature/readme",
        },
        agent_identities=identities,
        service=service,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body == {
        "status": "recorded",
        "audit_event_id": service.audit_events[0].event_id,
    }

    invalid = handle_v1_observe_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={"classification": "unmapped", "tool_input": "secret"},
        agent_identities=identities,
        service=service,
        now=NOW,
    )
    assert invalid.status_code == 400
    assert invalid.body["error"] == "invalid_request"
    assert len(service.audit_events) == 1


def test_observe_http_accepts_blocked_unmapped_outcome_without_disclosure() -> None:
    service = InMemoryV1Service()

    response = handle_v1_observe_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={"classification": "unmapped", "outcome": "blocked_unmapped"},
        agent_identities={
            "agent_key_main": AgentIdentity(
                workspace_id="ws_main",
                agent_id="agent_release",
            )
        },
        service=service,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body == {
        "status": "recorded",
        "audit_event_id": service.audit_events[0].event_id,
    }
    assert set(response.body) == {"status", "audit_event_id"}


def test_observe_http_rejects_invalid_mapping_without_audit() -> None:
    service = InMemoryV1Service()

    response = handle_v1_observe_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={"classification": "mapped", "action": "unknown", "resource": "repo/x"},
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
