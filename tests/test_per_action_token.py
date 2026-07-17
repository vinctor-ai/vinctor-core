from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_core.audit import REASON_SUBJECT_TOKEN_INVALID
from vinctor_service import (
    AgentIdentity,
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    InMemoryV1Service,
    V1DelegatedEnforceRequest,
    handle_v1_tokens_http,
)
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken
from vinctor_service.repositories import InMemorySubjectTokenRepository
from vinctor_service.v1_enforce import delegated_enforce_v1_contract

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _grant() -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def _request(
    *,
    subject_token: str,
    action: str = "write",
    resource: str = "repo/feature/readme",
) -> V1DelegatedEnforceRequest:
    return V1DelegatedEnforceRequest(
        pep_id="pep_git_host",
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        action=action,
        resource=resource,
        subject_token=subject_token,
    )


def _token_repo(
    *,
    bound_action: str | None = None,
    bound_resource: str | None = None,
) -> tuple[str, InMemorySubjectTokenRepository]:
    raw = _new_key("vat_")
    token = SubjectToken(
        token_id=_new_key("vtk_"),
        token_hash=_hash_key(raw),
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        created_by="agent_release",
        bound_action=bound_action,
        bound_resource=bound_resource,
    )
    return raw, InMemorySubjectTokenRepository((token,))


def _enforce(raw, repo, **over):
    return delegated_enforce_v1_contract(
        _request(subject_token=raw, **over),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=InMemoryAuditWriter(),
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )


def test_bound_token_for_exact_action_resource_permits() -> None:
    raw, repo = _token_repo(bound_action="write", bound_resource="repo/feature/readme")
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        _request(subject_token=raw, action="write", resource="repo/feature/readme"),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.decision == "permit"
    assert audit.events[0].identity_proven is True


def test_bound_token_for_different_action_denies_invalid_no_leak() -> None:
    raw, repo = _token_repo(bound_action="write", bound_resource="repo/feature/readme")
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        _request(subject_token=raw, action="read", resource="repo/feature/readme"),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events[0].reason_code == REASON_SUBJECT_TOKEN_INVALID
    # the bound action/resource must never leak into the response
    assert "write" not in str(response.reason)


def test_bound_token_for_different_resource_denies_invalid() -> None:
    raw, repo = _token_repo(bound_action="write", bound_resource="repo/feature/readme")
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        _request(subject_token=raw, action="write", resource="repo/feature/other"),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events[0].reason_code == REASON_SUBJECT_TOKEN_INVALID


def test_unbound_token_works_for_any_covered_action_resource() -> None:
    # UNBOUND == UNCHANGED: a token with both columns NULL authorizes the grant's
    # full scope exactly as today.
    raw, repo = _token_repo()
    response = _enforce(raw, repo, action="write", resource="repo/feature/anything")
    assert response.decision == "permit"


def _identities():
    return {"agent_key_main": AgentIdentity(workspace_id="ws_main", agent_id="agent_release")}


def _http_mint(svc, body):
    return handle_v1_tokens_http(
        headers={"X-Agent-Key": "agent_key_main"},
        body=body,
        agent_identities=_identities(),
        service=svc,
        now=NOW,
    )


def test_http_mint_with_action_and_resource_returns_201() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _http_mint(
        svc,
        {
            "grant_ref": "grt_main",
            "audience": "pep_git_host",
            "ttl_seconds": 300,
            "action": "write",
            "resource": "repo/feature/readme",
        },
    )
    assert r.status_code == 201
    token = svc.subject_token_repository.get_by_id(r.body["token_id"])
    assert token.bound_action == "write"
    assert token.bound_resource == "repo/feature/readme"


def test_http_mint_with_only_action_returns_400() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _http_mint(
        svc,
        {
            "grant_ref": "grt_main",
            "audience": "pep_git_host",
            "ttl_seconds": 300,
            "action": "write",
        },
    )
    assert r.status_code == 400
    assert r.body["error"] == "invalid_request"
