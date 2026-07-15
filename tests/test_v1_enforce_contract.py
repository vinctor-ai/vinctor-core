from datetime import UTC, datetime, timedelta

from vinctor_core import (
    BoundaryRegistrationInput,
    BoundaryRegistry,
    Grant,
    register_boundary,
)
from vinctor_core.audit import (
    EVENT_ACCESS_REJECTED,
    REASON_AGENT_GRANT_MISMATCH,
    AuditEvent,
)
from vinctor_service import (
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    V1EnforceRequest,
    enforce_v1_contract,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant(
    *,
    grant_id: str = "grnt_main",
    grant_ref: str = "grt_main",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    scopes: tuple[str, ...] = ("write:repo/feature/*",),
    status: str = "active",
    expires_at: datetime | None = None,
) -> Grant:
    return Grant(
        grant_id=grant_id,
        grant_ref=grant_ref,
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=scopes,
        status=status,
        expires_at=expires_at or NOW + timedelta(hours=1),
    )


def request(
    *,
    grant_ref: str = "grt_main",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    action: str = "write",
    resource: str = "repo/feature/readme",
    boundary_id: str | None = None,
) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_ref=grant_ref,
        action=action,
        resource=resource,
        boundary_id=boundary_id,
    )


class FailingGrantRepository:
    def get_by_ref(self, grant_ref: str) -> Grant | None:
        raise RuntimeError(f"lookup failed for {grant_ref}")


class FailingAuditWriter:
    def write(self, event: AuditEvent) -> None:
        raise RuntimeError(f"storage unavailable for {event.event_id}")


def repository(*grants: Grant) -> InMemoryGrantRepository:
    return InMemoryGrantRepository(grants)


def test_v1_enforce_permit_writes_audit_before_returning_decision() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].decision == "permit"
    assert audit.events[0].scope_matched == "write:repo/feature/*"


def test_v1_enforce_scope_deny_writes_audit_event() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "action_denied"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].reason == "action_denied"


def test_v1_enforce_grant_not_found_returns_403_and_records_rejection() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    # Existence oracle closed: an unknown grant returns the same generic 403
    # forbidden as a foreign grant AND writes the same coarse mismatch audit
    # (attributed to the caller), so it is indistinguishable by response and by
    # latency. It never echoes the grant_ref.
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert "grt_missing" not in (response.reason or "")
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.event_type == EVENT_ACCESS_REJECTED
    assert event.reason_code == REASON_AGENT_GRANT_MISMATCH
    assert event.grant_ref == ""
    assert "grt_" not in str(event.to_dict())


def test_v1_enforce_unknown_and_foreign_grant_are_indistinguishable() -> None:
    # A probe with a nonexistent grant_ref and a probe with an existing-but-foreign
    # grant_ref must receive an IDENTICAL caller-facing response (status + body),
    # so existence cannot be inferred from the response.
    unknown = enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=InMemoryAuditWriter(),
    )
    foreign = enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=InMemoryAuditWriter(),
    )

    assert unknown.status_code == foreign.status_code == 403
    assert unknown.error == foreign.error == "forbidden"
    assert unknown.reason == foreign.reason
    assert unknown.decision is foreign.decision is None


def test_v1_enforce_unknown_and_foreign_grant_write_identical_rejection_audit() -> None:
    # Timing-oracle regression (Codex red-team 2026-07-12): the caller-facing
    # response was already identical, but the UNKNOWN case wrote no audit while
    # the FOREIGN case wrote one — that audit-write asymmetry was a measurable
    # ~387us latency oracle for grant existence. Both cases must now traverse the
    # SAME audit-write path so they are indistinguishable by latency too. The
    # rejection is attributed to the caller's own workspace in both cases (never
    # the victim grant's), so no cross-tenant data is written.
    unknown_audit = InMemoryAuditWriter()
    enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=unknown_audit,
    )
    foreign_audit = InMemoryAuditWriter()
    enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=foreign_audit,
    )

    assert len(unknown_audit.events) == len(foreign_audit.events) == 1
    u, f = unknown_audit.events[0], foreign_audit.events[0]
    assert u.event_type == f.event_type == EVENT_ACCESS_REJECTED
    assert u.reason_code == f.reason_code == REASON_AGENT_GRANT_MISMATCH
    # Same coarse reason for both → the audit is not an exist-vs-not oracle either.
    assert u.reason == f.reason
    assert u.grant_ref == f.grant_ref == ""
    assert "grt_" not in str(u.to_dict())
    assert u.workspace_id == f.workspace_id  # caller's own workspace, not the victim's


def test_v1_enforce_grant_lookup_failure_returns_503_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(),
        grant_repository=FailingGrantRepository(),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 503
    assert response.error == "service_unavailable"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_missing_grant_precedes_invalid_request_validation() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(grant_ref="grt_missing", action="push", resource="repo"),
        grant_repository=repository(),
        now=NOW,
        audit_writer=audit,
    )

    # The missing-grant forbidden precedes invalid-request validation (an invalid
    # action here never surfaces), and records the coarse rejection audit.
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert len(audit.events) == 1
    assert audit.events[0].reason_code == REASON_AGENT_GRANT_MISMATCH


def test_v1_enforce_cross_agent_misuse_records_rejection_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    # ADR 0008: the cross-agent grant-misuse attempt is audited for the operator,
    # attributable to the caller and without disclosing the grant.
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.event_type == EVENT_ACCESS_REJECTED
    assert event.reason_code == REASON_AGENT_GRANT_MISMATCH
    assert event.reason == REASON_AGENT_GRANT_MISMATCH
    assert event.agent_id == "agent_other"
    assert event.grant_ref == ""
    assert "grt_" not in str(event.to_dict())


def test_v1_enforce_wrong_workspace_records_rejection_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(workspace_id="ws_other"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.event_type == EVENT_ACCESS_REJECTED
    assert event.reason_code == REASON_AGENT_GRANT_MISMATCH
    assert event.reason == REASON_AGENT_GRANT_MISMATCH
    assert event.workspace_id == "ws_other"
    assert event.grant_ref == ""
    assert "grt_" not in str(event.to_dict())


def test_v1_enforce_invalid_action_maps_to_scope_invalid_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(action="push", resource="repo/main"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 400
    assert response.error == "scope_invalid"
    assert "push" in response.reason
    assert "write" in response.reason
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_invalid_resource_maps_to_scope_invalid_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(resource="repo"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 400
    assert response.error == "scope_invalid"
    assert response.decision is None
    assert audit.events == []


def test_v1_enforce_revoked_grant_writes_deny_audit() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(),
        grant_repository=repository(grant(status="revoked")),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "grant_revoked"
    assert audit.events[0].reason == "grant_revoked"


def test_v1_enforce_audit_failure_returns_503_without_decision() -> None:
    response = enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=FailingAuditWriter(),
    )

    assert response.status_code == 503
    assert response.error == "service_unavailable"
    assert response.decision is None
    assert response.audit_event_id is None


def test_v1_enforce_boundary_denial_writes_audit_event() -> None:
    audit = InMemoryAuditWriter()

    response = enforce_v1_contract(
        request(boundary_id="bnd_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        boundary_registry=BoundaryRegistry(),
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "boundary_unavailable"
    assert response.audit_event_id == audit.events[0].event_id
    assert audit.events[0].reason == "boundary_not_found"  # audit keeps precise
    assert audit.events[0].boundary_id == "bnd_missing"


def test_v1_enforce_boundary_denials_do_not_reveal_existence() -> None:
    # A boundary that is ABSENT and one that EXISTS in another workspace must
    # return the SAME agent-facing reason, so an agent cannot enumerate which
    # boundary ids exist across workspaces from the deny response. The operator
    # audit still distinguishes the two cases precisely.
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_other",
            name="langgraph-local",
            runtime="langgraph",
            boundary_type="middleware",
        ),
        now=NOW,
        boundary_id="bnd_other_ws",
    )

    absent_audit = InMemoryAuditWriter()
    absent = enforce_v1_contract(
        request(boundary_id="bnd_absent"),
        grant_repository=repository(grant()),  # grant is in ws_main
        now=NOW,
        audit_writer=absent_audit,
        boundary_registry=registry,
    )
    cross_tenant_audit = InMemoryAuditWriter()
    cross_tenant = enforce_v1_contract(
        request(boundary_id="bnd_other_ws"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=cross_tenant_audit,
        boundary_registry=registry,
    )

    # Agent-facing responses are indistinguishable (oracle closed)...
    assert absent.error == cross_tenant.error == "boundary_unavailable"
    assert absent.reason == cross_tenant.reason == "boundary_unavailable"
    # ...while the operator audit keeps the precise, distinct reasons.
    assert absent_audit.events[0].reason == "boundary_not_found"
    assert cross_tenant_audit.events[0].reason == "boundary_wrong_workspace"


def test_in_memory_audit_writer_records_events_in_order() -> None:
    audit = InMemoryAuditWriter()

    first = enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )
    second = enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert [event.event_id for event in audit.events] == [
        first.audit_event_id,
        second.audit_event_id,
    ]


def test_in_memory_grant_repository_rejects_duplicate_grant_refs() -> None:
    duplicate = grant(grant_id="grnt_duplicate")

    try:
        InMemoryGrantRepository((grant(), duplicate))
    except ValueError as error:
        assert "duplicate grant_ref" in str(error)
    else:
        raise AssertionError("expected duplicate grant_ref to be rejected")
