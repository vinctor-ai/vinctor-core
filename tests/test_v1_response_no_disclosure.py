"""No-disclosure contract for agent-facing /v1/enforce and /v1/simulate responses.

An agent holds its own agent key and can call the core directly, bypassing any
PEP/hook that would discard detail. The enforce/simulate RESPONSE must therefore
never teach the agent the classified action/resource, the grant's scopes, or any
internal identifier (grant_id / grant_ref / agent_id / boundary_id /
scope_matched). It may carry ONLY: the decision (or would_decision), a coarse
low-cardinality reason code, and the audit_event_id.

The operator AUDIT event is the opposite surface: it MUST keep the full detail
(grant_id, action, resource, scope_attempted, ...). Every test here asserts both
sides so a fix can never "pass" by weakening the audit.
"""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_service import (
    AgentIdentity,
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    InMemoryV1Service,
    PepIdentity,
    V1EnforceRequest,
    V1SimulateRequest,
    enforce_v1_contract,
    handle_v1_delegated_enforce_http,
    handle_v1_enforce_http,
    handle_v1_simulate_http,
    simulate_v1_contract,
)

NOW = datetime(2026, 7, 14, 12, 0, tzinfo=UTC)

# Deliberately distinctive probe values. None of these may appear anywhere in an
# agent-facing response. (The bare action verb "write" is not marker-checked
# because coarse codes legitimately contain words; the classified pair is
# covered by SCOPE_ATTEMPTED and PROBE_RESOURCE instead.)
GRANT_ID = "grnt_topsecret_internal"
GRANT_REF = "grt_probe_ref"
GRANT_SCOPE = "read:repo/feature/*"
PROBE_ACTION = "write"
PROBE_RESOURCE = "repo/PROBE_TARGET"
SCOPE_ATTEMPTED = f"{PROBE_ACTION}:{PROBE_RESOURCE}"
LEAK_MARKERS = (GRANT_ID, GRANT_REF, "grnt_", "grt_", GRANT_SCOPE, PROBE_RESOURCE, SCOPE_ATTEMPTED)

INTERNAL_FIELDS = ("grant_id", "grant_ref", "agent_id", "boundary_id", "scope_matched")


def grant() -> Grant:
    return Grant(
        grant_id=GRANT_ID,
        grant_ref=GRANT_REF,
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=(GRANT_SCOPE,),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def deny_request() -> V1EnforceRequest:
    # Unmatched scope: the grant only covers GRANT_SCOPE.
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref=GRANT_REF,
        action=PROBE_ACTION,
        resource=PROBE_RESOURCE,
    )


def permit_request() -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref=GRANT_REF,
        action="read",
        resource="repo/feature/readme",
    )


def _assert_no_disclosure(response: object) -> None:
    """The response object exposes no internal field and no leak-marker value."""
    for field in INTERNAL_FIELDS:
        assert getattr(response, field, None) is None, f"response exposes {field}"
    blob = asdict(response)  # type: ignore[call-overload]
    blob.pop("audit_event_id", None)  # random evt_ id; not derived from secrets
    text = str(blob)
    for marker in LEAK_MARKERS:
        assert marker not in text, f"response leaks {marker!r}: {text}"


def _assert_body_no_disclosure(body: dict) -> None:
    """The HTTP JSON body carries no internal key and no leak-marker value."""
    for field in INTERNAL_FIELDS:
        assert field not in body, f"body exposes key {field}"
    scrubbed = {key: value for key, value in body.items() if key != "audit_event_id"}
    text = str(scrubbed)
    for marker in LEAK_MARKERS:
        assert marker not in text, f"body leaks {marker!r}: {text}"


def test_enforce_deny_response_is_coarse_and_audit_keeps_detail() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        deny_request(),
        grant_repository=InMemoryGrantRepository((grant(),)),
        now=NOW,
        audit_writer=audit,
    )

    # Agent-facing: decision + coarse reason code + audit_event_id, nothing else.
    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.reason == "action_denied"
    assert response.error == "action_denied"
    assert response.audit_event_id == audit.events[0].event_id
    _assert_no_disclosure(response)

    # Operator-facing audit: full detail is retained.
    event = audit.events[0]
    assert event.reason == "action_denied"
    assert event.grant_id == GRANT_ID
    assert event.grant_ref == GRANT_REF
    assert event.action == PROBE_ACTION
    assert event.resource == PROBE_RESOURCE
    assert event.scope_attempted == SCOPE_ATTEMPTED
    assert event.scope_matched is None


def test_enforce_permit_response_is_coarse_and_audit_keeps_detail() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        permit_request(),
        grant_repository=InMemoryGrantRepository((grant(),)),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    assert response.audit_event_id == audit.events[0].event_id
    _assert_no_disclosure(response)

    event = audit.events[0]
    assert event.grant_id == GRANT_ID
    assert event.grant_ref == GRANT_REF
    assert event.scope_matched == GRANT_SCOPE


def test_simulate_would_deny_response_is_coarse_and_audit_keeps_detail() -> None:
    audit = InMemoryAuditWriter()

    response = simulate_v1_contract(
        V1SimulateRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref=GRANT_REF,
            action=PROBE_ACTION,
            resource=PROBE_RESOURCE,
        ),
        grant_repository=InMemoryGrantRepository((grant(),)),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 200
    assert response.would_decision == "deny"
    assert response.reason == "action_denied"
    assert response.audit_event_id == audit.events[0].event_id
    _assert_no_disclosure(response)

    event = audit.events[0]
    assert event.event_type == "action_would_deny"
    assert event.grant_id == GRANT_ID
    assert event.grant_ref == GRANT_REF
    assert event.action == PROBE_ACTION
    assert event.resource == PROBE_RESOURCE
    assert event.scope_attempted == SCOPE_ATTEMPTED


def test_simulate_would_permit_response_is_coarse() -> None:
    audit = InMemoryAuditWriter()

    response = simulate_v1_contract(
        V1SimulateRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            grant_ref=GRANT_REF,
            action="read",
            resource="repo/feature/readme",
        ),
        grant_repository=InMemoryGrantRepository((grant(),)),
        now=NOW,
        audit_writer=audit,
    )

    assert response.would_decision == "permit"
    _assert_no_disclosure(response)
    # The grant's matched scope stays in the audit, never in the response.
    assert audit.events[0].scope_matched == GRANT_SCOPE


def _service() -> InMemoryV1Service:
    return InMemoryV1Service(grants=(grant(),))


def _agent_identities() -> dict[str, AgentIdentity]:
    return {
        "agent_key_main": AgentIdentity(workspace_id="ws_main", agent_id="agent_release")
    }


def test_enforce_http_deny_body_is_coarse() -> None:
    svc = _service()

    response = handle_v1_enforce_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={"grant_ref": GRANT_REF, "action": PROBE_ACTION, "resource": PROBE_RESOURCE},
        agent_identities=_agent_identities(),
        service=svc,
        now=NOW,
    )

    assert response.status_code == 403
    assert response.body == {
        "decision": "deny",
        "error": "action_denied",
        "reason": "action_denied",
        "audit_event_id": svc.audit_events[0].event_id,
    }
    _assert_body_no_disclosure(response.body)
    # Audit keeps the detail the body no longer carries.
    assert svc.audit_events[0].grant_id == GRANT_ID
    assert svc.audit_events[0].scope_attempted == SCOPE_ATTEMPTED


def test_enforce_http_permit_body_is_coarse() -> None:
    svc = _service()

    response = handle_v1_enforce_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={"grant_ref": GRANT_REF, "action": "read", "resource": "repo/feature/readme"},
        agent_identities=_agent_identities(),
        service=svc,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body == {
        "decision": "permit",
        "audit_event_id": svc.audit_events[0].event_id,
    }
    _assert_body_no_disclosure(response.body)
    assert svc.audit_events[0].grant_id == GRANT_ID
    assert svc.audit_events[0].scope_matched == GRANT_SCOPE


def test_simulate_http_would_deny_body_is_coarse() -> None:
    svc = _service()

    response = handle_v1_simulate_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={"grant_ref": GRANT_REF, "action": PROBE_ACTION, "resource": PROBE_RESOURCE},
        agent_identities=_agent_identities(),
        service=svc,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body == {
        "status": "simulated",
        "would_decision": "deny",
        "error": "action_denied",
        "reason": "action_denied",
        "audit_event_id": svc.audit_events[0].event_id,
    }
    _assert_body_no_disclosure(response.body)
    assert svc.audit_events[0].grant_id == GRANT_ID
    assert svc.audit_events[0].scope_attempted == SCOPE_ATTEMPTED


def test_simulate_http_would_permit_body_is_coarse() -> None:
    svc = _service()

    response = handle_v1_simulate_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body={"grant_ref": GRANT_REF, "action": "read", "resource": "repo/feature/readme"},
        agent_identities=_agent_identities(),
        service=svc,
        now=NOW,
    )

    assert response.status_code == 200
    assert response.body == {
        "status": "simulated",
        "would_decision": "permit",
        "error": None,
        "reason": None,
        "audit_event_id": svc.audit_events[0].event_id,
    }
    _assert_body_no_disclosure(response.body)
    assert svc.audit_events[0].scope_matched == GRANT_SCOPE


def test_delegated_enforce_http_bodies_are_coarse() -> None:
    # /v1/enforce/delegated shares the enforce response builder; pin it to the
    # same no-disclosure contract on both the permit and the deny path.
    svc = _service()
    pep_identities = {"pep_key_main": PepIdentity(workspace_id="ws_main", pep_id="pep_git_host")}

    denied = handle_v1_delegated_enforce_http(
        headers={"X-PEP-Key": "pep_key_main"},
        body={
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "grant_ref": GRANT_REF,
            "action": PROBE_ACTION,
            "resource": PROBE_RESOURCE,
        },
        pep_identities=pep_identities,
        service=svc,
        now=NOW,
    )
    permitted = handle_v1_delegated_enforce_http(
        headers={"X-PEP-Key": "pep_key_main"},
        body={
            "workspace_id": "ws_main",
            "agent_id": "agent_release",
            "grant_ref": GRANT_REF,
            "action": "read",
            "resource": "repo/feature/readme",
        },
        pep_identities=pep_identities,
        service=svc,
        now=NOW,
    )

    assert denied.status_code == 403
    assert denied.body["decision"] == "deny"
    assert denied.body["reason"] == "action_denied"
    _assert_body_no_disclosure(denied.body)
    assert permitted.status_code == 200
    assert permitted.body["decision"] == "permit"
    _assert_body_no_disclosure(permitted.body)
    # The audit trail keeps full detail for both decisions.
    assert svc.audit_events[0].grant_id == GRANT_ID
    assert svc.audit_events[0].resource == PROBE_RESOURCE
    assert svc.audit_events[1].grant_id == GRANT_ID
    assert svc.audit_events[1].scope_matched == GRANT_SCOPE
