from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_service import (
    InMemoryAuditWriter,
    InMemoryGrantRepository,
)
from vinctor_service.models import V1DelegatedEnforceRequest
from vinctor_service.v1_enforce import delegated_enforce_v1_contract

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant(
    *,
    grant_id: str = "grnt_main",
    grant_ref: str = "grt_main",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    scopes: tuple[str, ...] = ("write:repo/feature/*",),
    status: str = "active",
) -> Grant:
    return Grant(
        grant_id=grant_id,
        grant_ref=grant_ref,
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=scopes,
        status=status,
        expires_at=NOW + timedelta(hours=1),
    )


def request(
    *,
    pep_id: str = "pep_git_host",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    grant_ref: str = "grt_main",
    action: str = "write",
    resource: str = "repo/feature/readme",
    boundary_id: str | None = None,
    pep_workspace_id: str | None = "ws_main",
) -> V1DelegatedEnforceRequest:
    # ``pep_workspace_id`` mirrors what the HTTP handler always forces from the
    # authenticated PEP key (see handle_v1_delegated_enforce_http). It defaults
    # to the trusted workspace so the happy paths reflect production; tests that
    # want to exercise the missing-trusted-identity case pass ``None``.
    return V1DelegatedEnforceRequest(
        pep_id=pep_id,
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_ref=grant_ref,
        action=action,
        resource=resource,
        boundary_id=boundary_id,
        pep_workspace_id=pep_workspace_id,
    )


def repository(*grants: Grant) -> InMemoryGrantRepository:
    return InMemoryGrantRepository(grants)


def test_delegated_enforce_permit_records_pep_principal() -> None:
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    assert response.agent_id == "agent_release"
    assert response.audit_event_id == audit.events[0].event_id
    # Subject is the agent; the enforcing principal is the PEP, recorded separately.
    assert audit.events[0].agent_id == "agent_release"
    assert audit.events[0].enforcing_principal == "pep_git_host"


def test_delegated_enforce_scope_deny_records_audit() -> None:
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "action_denied"
    assert audit.events[0].enforcing_principal == "pep_git_host"


def test_delegated_enforce_cross_workspace_grant_is_forbidden_without_audit() -> None:
    audit = InMemoryAuditWriter()

    # PEP authenticated for ws_main (its key-derived pep_workspace_id) asserts a
    # subject/grant in ws_other. This exercises the DEFAULT path: the trusted
    # workspace is taken from the request's pep_workspace_id (as the HTTP handler
    # sets it), not from a manually injected kwarg.
    response = delegated_enforce_v1_contract(
        request(
            workspace_id="ws_other",
            agent_id="agent_release",
            pep_workspace_id="ws_main",
        ),
        grant_repository=repository(grant(workspace_id="ws_other")),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_delegated_enforce_missing_trusted_pep_workspace_fails_closed() -> None:
    """Regression: with no trusted PEP workspace the contract must DENY.

    The original implementation fell back to the caller-asserted
    ``request.workspace_id`` when no trusted PEP workspace was supplied, making
    the isolation gate trivially pass. A caller could thus authorize a grant in
    any workspace. This asserts the fail-closed behavior: deny with no audit.
    """
    audit = InMemoryAuditWriter()

    # No trusted PEP workspace: neither the request field nor the kwarg is set.
    # The grant fully matches the caller-asserted workspace/agent, which the
    # fail-open bug would have accepted.
    response = delegated_enforce_v1_contract(
        request(workspace_id="ws_main", agent_id="agent_release", pep_workspace_id=None),
        grant_repository=repository(grant(workspace_id="ws_main", agent_id="agent_release")),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_delegated_enforce_caller_asserted_workspace_cannot_override_trusted() -> None:
    """A caller-asserted workspace can never override the trusted PEP workspace.

    The trusted workspace (ws_main, from the PEP identity) governs; the grant
    lives in ws_main, but the caller asserts ws_other. This must DENY even
    though a matching grant exists in the trusted workspace, because the
    asserted workspace disagrees with the trusted one.
    """
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(
            workspace_id="ws_other",
            agent_id="agent_release",
            pep_workspace_id="ws_main",
        ),
        grant_repository=repository(grant(workspace_id="ws_main", agent_id="agent_release")),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_delegated_enforce_subject_mismatch_is_forbidden_without_audit() -> None:
    audit = InMemoryAuditWriter()

    # Grant belongs to a different agent than the asserted subject.
    response = delegated_enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant(agent_id="agent_release")),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_delegated_enforce_missing_grant_returns_404_without_audit() -> None:
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 404
    assert response.error == "grant_not_found"
    assert response.decision is None
    assert audit.events == []


def test_delegated_enforce_does_not_disclose_grant_ref_in_response() -> None:
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
    )

    assert "grt_main" not in (response.reason or "")
    assert "grt_main" not in (response.error or "")
