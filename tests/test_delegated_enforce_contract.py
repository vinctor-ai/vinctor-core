import dataclasses
from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_core.audit import (
    EVENT_ACCESS_REJECTED,
    REASON_AGENT_GRANT_MISMATCH,
    REASON_POP_REQUIRED,
    REASON_SUBJECT_TOKEN_INVALID,
)
from vinctor_service import (
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    InMemoryV1Service,
    SQLiteV1Service,
)
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken, V1DelegatedEnforceRequest
from vinctor_service.pop import pop_canonical, pop_mac
from vinctor_service.repositories import (
    InMemoryAgentEnforcementSettingsRepository,
    InMemorySubjectTokenRepository,
)
from vinctor_service.sqlite_txn import connect_sqlite
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
    subject_token: str | None = None,
) -> V1DelegatedEnforceRequest:
    # Every DTO field is caller-asserted. The TRUSTED PEP workspace is not part
    # of the request: it is the ``pep_workspace_id`` ARGUMENT of the contract
    # (the HTTP handler derives it from the authenticated PEP key), so tests
    # pass it per-call.
    return V1DelegatedEnforceRequest(
        pep_id=pep_id,
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_ref=grant_ref,
        action=action,
        resource=resource,
        boundary_id=boundary_id,
        subject_token=subject_token,
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
        pep_workspace_id="ws_main",
    )

    assert response.status_code == 200
    assert response.decision == "permit"
    assert response.audit_event_id == audit.events[0].event_id
    # Subject is the agent; the enforcing principal is the PEP, recorded separately.
    # (Both live in the audit only — the response is a no-disclosure surface.)
    assert audit.events[0].agent_id == "agent_release"
    assert audit.events[0].enforcing_principal == "pep_git_host"


def test_delegated_enforce_scope_deny_records_audit() -> None:
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    assert response.status_code == 403
    assert response.decision == "deny"
    assert response.error == "action_denied"
    assert audit.events[0].enforcing_principal == "pep_git_host"


def test_delegated_enforce_cross_workspace_grant_records_rejection_audit() -> None:
    audit = InMemoryAuditWriter()

    # PEP authenticated for ws_main (the key-derived pep_workspace_id argument,
    # exactly as the HTTP handler passes it) asserts a subject/grant in
    # ws_other.
    response = delegated_enforce_v1_contract(
        request(workspace_id="ws_other", agent_id="agent_release"),
        grant_repository=repository(grant(workspace_id="ws_other")),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    # ADR 0008: a PEP asserting a subject/grant outside its workspace is audited.
    assert len(audit.events) == 1
    assert audit.events[0].event_type == EVENT_ACCESS_REJECTED
    assert audit.events[0].reason_code == REASON_AGENT_GRANT_MISMATCH
    assert audit.events[0].reason == REASON_AGENT_GRANT_MISMATCH
    assert audit.events[0].enforcing_principal == "pep_git_host"
    assert audit.events[0].grant_ref == ""


def test_delegated_enforce_missing_trusted_pep_workspace_fails_closed() -> None:
    """Regression: with no trusted PEP workspace the contract must DENY.

    The original implementation fell back to the caller-asserted
    ``request.workspace_id`` when no trusted PEP workspace was supplied, making
    the isolation gate trivially pass. A caller could thus authorize a grant in
    any workspace. This asserts the fail-closed behavior: deny with no audit.
    """
    audit = InMemoryAuditWriter()

    # No trusted PEP workspace argument (and the request DTO carries none by
    # construction). The grant fully matches the caller-asserted
    # workspace/agent, which the fail-open bug would have accepted.
    response = delegated_enforce_v1_contract(
        request(workspace_id="ws_main", agent_id="agent_release"),
        grant_repository=repository(grant(workspace_id="ws_main", agent_id="agent_release")),
        now=NOW,
        audit_writer=audit,
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events == []


def test_delegated_enforce_cannot_self_assert_trusted_workspace() -> None:
    """SECURITY acceptance: a direct/library caller cannot authorize a grant by
    self-asserting the trusted PEP workspace.

    Trust comes ONLY from the authenticated ``pep_workspace_id`` ARGUMENT (the
    key-derived identity the auth layer passes) — never from anything in the
    request body. Here a fully matching grant exists in the asserted workspace
    and the caller fills every field the public DTO exposes, but supplies no
    authenticated workspace argument: the contract must fail closed (403, no
    permit). The DTO itself must not carry a trusted-workspace field, so the
    trusted value and the caller-controlled values stay structurally
    distinguishable (argument vs body).
    """
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(),  # caller-controlled fields only — nothing authenticated
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        # Deliberately NO pep_workspace_id argument.
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None  # never a permit
    assert "pep_workspace_id" not in {
        f.name for f in dataclasses.fields(V1DelegatedEnforceRequest)
    }


def test_delegated_enforce_authenticated_workspace_argument_permits() -> None:
    """Correct path: the auth layer passes the key-derived workspace as the
    explicit ``pep_workspace_id`` argument; a valid same-workspace grant
    permits."""
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    assert response.status_code == 200
    assert response.decision == "permit"


def test_delegated_enforce_caller_asserted_workspace_cannot_override_trusted() -> None:
    """A caller-asserted workspace can never override the trusted PEP workspace.

    The trusted workspace (ws_main, from the PEP identity) governs; the grant
    lives in ws_main, but the caller asserts ws_other. This must DENY even
    though a matching grant exists in the trusted workspace, because the
    asserted workspace disagrees with the trusted one.
    """
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(workspace_id="ws_other", agent_id="agent_release"),
        grant_repository=repository(grant(workspace_id="ws_main", agent_id="agent_release")),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    # ADR 0008: still denied AND now audited (cross-workspace assertion attempt).
    assert len(audit.events) == 1
    assert audit.events[0].reason_code == REASON_AGENT_GRANT_MISMATCH
    assert audit.events[0].reason == REASON_AGENT_GRANT_MISMATCH
    assert audit.events[0].enforcing_principal == "pep_git_host"


def test_delegated_enforce_subject_mismatch_records_rejection_audit() -> None:
    audit = InMemoryAuditWriter()

    # Grant belongs to a different agent than the asserted subject.
    response = delegated_enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant(agent_id="agent_release")),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    # ADR 0008: audited for the operator; PEP recorded as the enforcing principal.
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.event_type == EVENT_ACCESS_REJECTED
    assert event.reason_code == REASON_AGENT_GRANT_MISMATCH
    assert event.reason == REASON_AGENT_GRANT_MISMATCH
    assert event.agent_id == "agent_other"
    assert event.enforcing_principal == "pep_git_host"
    assert event.grant_ref == ""
    assert "grt_" not in str(event.to_dict())


def test_delegated_enforce_missing_grant_returns_403_and_records_rejection() -> None:
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    # Existence oracle closed: an unknown grant returns the same generic 403
    # forbidden as a foreign grant AND writes the same coarse mismatch audit
    # (indistinguishable by response and by latency), never echoing the grant_ref.
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert "grt_missing" not in (response.reason or "")
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.reason_code == REASON_AGENT_GRANT_MISMATCH
    assert event.grant_ref == ""
    assert "grt_" not in str(event.to_dict())


def test_delegated_enforce_unknown_and_foreign_grant_are_indistinguishable() -> None:
    # A probe with a nonexistent grant_ref and a probe with an existing-but-foreign
    # grant_ref (here: belonging to a different agent in the trusted workspace) must
    # receive an IDENTICAL caller-facing response. Existence cannot be inferred.
    unknown = delegated_enforce_v1_contract(
        request(grant_ref="grt_missing"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=InMemoryAuditWriter(),
        pep_workspace_id="ws_main",
    )
    foreign = delegated_enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant(agent_id="agent_release")),
        now=NOW,
        audit_writer=InMemoryAuditWriter(),
        pep_workspace_id="ws_main",
    )

    assert unknown.status_code == foreign.status_code == 403
    assert unknown.error == foreign.error == "forbidden"
    assert unknown.reason == foreign.reason
    assert unknown.decision is foreign.decision is None


def test_delegated_enforce_foreign_grant_audit_uses_trusted_workspace() -> None:
    # The mismatch audit for an existing-but-foreign grant must be attributed to the
    # caller's OWN authenticated (trusted) workspace, never the victim grant's
    # workspace, so a probe cannot write into another workspace's audit trail.
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(agent_id="agent_other"),
        grant_repository=repository(grant(workspace_id="ws_main", agent_id="agent_release")),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    assert response.status_code == 403
    assert response.error == "forbidden"
    assert len(audit.events) == 1
    assert audit.events[0].reason_code == REASON_AGENT_GRANT_MISMATCH
    assert audit.events[0].workspace_id == "ws_main"
    assert audit.events[0].enforcing_principal == "pep_git_host"


def test_delegated_enforce_does_not_disclose_grant_ref_in_response() -> None:
    audit = InMemoryAuditWriter()

    response = delegated_enforce_v1_contract(
        request(action="send", resource="email/external"),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )

    assert "grt_main" not in (response.reason or "")
    assert "grt_main" not in (response.error or "")


def _raw_and_repo(
    *,
    audience="pep_git_host",
    workspace_id="ws_main",
    agent_id="agent_release",
    grant_ref="grt_main",
    expires_at=None,
):
    raw = _new_key("vat_")
    token = SubjectToken(
        token_id=_new_key("vtk_"),
        token_hash=_hash_key(raw),
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_ref=grant_ref,
        audience=audience,
        issued_at=NOW,
        expires_at=expires_at or (NOW + timedelta(seconds=300)),
        created_by=agent_id,
    )
    repo = InMemorySubjectTokenRepository((token,))
    return raw, token, repo


def test_proven_path_permits_and_marks_subject_token_verified() -> None:
    audit = InMemoryAuditWriter()
    raw, token, repo = _raw_and_repo()
    response = delegated_enforce_v1_contract(
        request(subject_token=raw),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.decision == "permit"
    assert audit.events[0].subject_token_verified is True
    assert audit.events[0].token_id == token.token_id


def test_expired_token_fails_closed() -> None:
    audit = InMemoryAuditWriter()
    raw, _, repo = _raw_and_repo(expires_at=NOW - timedelta(seconds=1))
    response = delegated_enforce_v1_contract(
        request(subject_token=raw),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert audit.events[0].reason_code == REASON_SUBJECT_TOKEN_INVALID


def test_audience_mismatch_fails_closed() -> None:
    audit = InMemoryAuditWriter()
    raw, _, repo = _raw_and_repo(audience="pep_other_host")
    response = delegated_enforce_v1_contract(
        request(subject_token=raw),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.status_code == 403


def test_token_subject_mismatch_with_body_fails_closed() -> None:
    audit = InMemoryAuditWriter()
    # token says agent_other, body says agent_release
    raw, _, repo = _raw_and_repo(agent_id="agent_other")
    response = delegated_enforce_v1_contract(
        request(subject_token=raw),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.status_code == 403


def test_token_store_error_fails_closed_not_503() -> None:
    class Boom:
        def get_by_hash(self, token_hash):
            raise RuntimeError("store down")

    audit = InMemoryAuditWriter()
    raw, _, _ = _raw_and_repo()
    response = delegated_enforce_v1_contract(
        request(subject_token=raw),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=Boom(),
    )
    assert response.status_code == 403  # NOT 503, NOT a permit


def test_no_token_legacy_path_unchanged() -> None:
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        request(),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=InMemorySubjectTokenRepository(),
    )
    assert response.decision == "permit"
    assert audit.events[0].subject_token_verified is False
    assert "subject_token_verified" not in audit.events[0].to_dict()


# ---- require_pop mandate ---------------------------------------------------
# require_pop denies a PRESENTED non-PoP subject token (pop_secret is None). It is
# single-purpose: it does NOT govern the no-token case (that stays under
# require_subject_token). The deny is the SAME leak-free generic 403 forbidden as the
# other token denies; only the audit reason_code (pop_required) distinguishes it.


def _require_pop_settings() -> InMemoryAgentEnforcementSettingsRepository:
    settings = InMemoryAgentEnforcementSettingsRepository()
    settings.set_require_pop(
        workspace_id="ws_main", agent_id="agent_release", require_pop=True, now=NOW
    )
    return settings


def test_require_pop_denies_presented_non_pop_token() -> None:
    # require_pop ON + a valid-but-non-PoP token (pop_secret is None) => generic
    # 403 forbidden, audited pop_required, identity NOT proven.
    audit = InMemoryAuditWriter()
    raw, _token, repo = _raw_and_repo()
    response = delegated_enforce_v1_contract(
        request(subject_token=raw),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
        agent_enforcement_settings_repository=_require_pop_settings(),
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events[-1].reason_code == REASON_POP_REQUIRED
    # The deny must not leak that PoP specifically was the missing piece.
    assert "pop" not in (response.reason or "").lower() or "possession" in (
        response.reason or ""
    ).lower()
    # identity was never proven on a denied non-PoP token.
    assert audit.events[-1].subject_token_verified is not True


def test_require_pop_permits_pop_token_with_valid_proof() -> None:
    # require_pop ON + a PoP token (pop_secret set) + valid proof => unchanged permit.
    svc = InMemoryV1Service(grants=(grant(),))
    svc.agent_enforcement_settings_repository.set_require_pop(
        workspace_id="ws_main", agent_id="agent_release", require_pop=True, now=NOW
    )
    result = svc.mint_subject_token(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        ttl_seconds=300,
        now=NOW,
        pop=True,
    )
    assert result.pop_secret is not None
    ts = int(NOW.timestamp())
    mac = pop_mac(
        result.pop_secret,
        pop_canonical("write", "repo/feature/readme", ts, "n-1", result.token_id),
    )
    proof = f"{ts}.n-1.{mac}"
    # The local request() helper has no proof field; build directly so the PoP
    # proof reaches the enforce contract.
    pop_request = V1DelegatedEnforceRequest(
        pep_id="pep_git_host",
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        action="write",
        resource="repo/feature/readme",
        subject_token=result.token,
        subject_token_proof=proof,
    )
    r = svc.delegated_enforce(pop_request, now=NOW, pep_workspace_id="ws_main")
    assert r.decision == "permit"
    assert svc.audit_events[-1].subject_token_verified is True


def test_require_pop_off_permits_non_pop_token() -> None:
    # Default-off regression: no require_pop row => a non-PoP token still permits.
    audit = InMemoryAuditWriter()
    raw, token, repo = _raw_and_repo()
    response = delegated_enforce_v1_contract(
        request(subject_token=raw),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
        agent_enforcement_settings_repository=InMemoryAgentEnforcementSettingsRepository(),
    )
    assert response.decision == "permit"
    assert audit.events[-1].subject_token_verified is True
    assert audit.events[-1].token_id == token.token_id


def test_require_pop_alone_denies_missing_token() -> None:
    # require_pop implies a usable subject token MUST be presented: PoP can only be
    # proven on a token that exists. require_pop ON (even with require_subject_token
    # OFF) + NO token => fail-closed deny, audited pop_required. Closes the footgun
    # where enabling require_pop alone silently permitted an unproven no-token call.
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        request(subject_token=None),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=InMemorySubjectTokenRepository(),
        agent_enforcement_settings_repository=_require_pop_settings(),
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events[-1].reason_code == REASON_POP_REQUIRED
    assert audit.events[-1].subject_token_verified is not True


def test_require_pop_alone_denies_blank_token() -> None:
    # Empty == absent: a whitespace-only token header is no token, denied like None
    # (mirrors require_subject_token). Do NOT normalize blank->None elsewhere.
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        request(subject_token="   "),
        grant_repository=repository(grant()),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=InMemorySubjectTokenRepository(),
        agent_enforcement_settings_repository=_require_pop_settings(),
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events[-1].reason_code == REASON_POP_REQUIRED


def test_sqlite_require_pop_denies_presented_non_pop_token(tmp_path) -> None:
    # Pins the production (SQLite) wiring: the require_pop mandate is consulted on
    # the SQLite delegated path too, not only InMemory.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    service = SQLiteV1Service(conn)
    service.insert_grant(grant())
    service.agent_enforcement_settings_repository.set_require_pop(
        workspace_id="ws_main", agent_id="agent_release", require_pop=True, now=NOW
    )
    result = service.mint_subject_token(
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        ttl_seconds=300,
        now=NOW,
        pop=False,
    )
    assert result.pop_secret is None
    r = service.delegated_enforce(
        request(subject_token=result.token),
        now=NOW,
        pep_workspace_id="ws_main",
    )
    assert r.status_code == 403
    assert r.error == "forbidden"
    assert r.decision is None
    # On the SQLite path the operator-only rejection code round-trips via the
    # persisted ``reason`` field (reason_code is mirrored into it on rejection).
    assert service.audit_events[-1].reason == REASON_POP_REQUIRED
