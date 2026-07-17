from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_core.audit import REASON_SUBJECT_TOKEN_INVALID
from vinctor_service import InMemoryAuditWriter, InMemoryGrantRepository
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken, V1DelegatedEnforceRequest
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


def _request(raw: str) -> V1DelegatedEnforceRequest:
    return V1DelegatedEnforceRequest(
        pep_id="pep_git_host",
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        action="write",
        resource="repo/feature/readme",
        subject_token=raw,
    )


def _revoked_token_repo() -> tuple[str, InMemorySubjectTokenRepository]:
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
        revoked_at=NOW,
    )
    return raw, InMemorySubjectTokenRepository((token,))


def test_revoked_token_fails_closed_as_invalid() -> None:
    audit = InMemoryAuditWriter()
    raw, repo = _revoked_token_repo()
    response = delegated_enforce_v1_contract(
        _request(raw),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert audit.events[0].reason_code == REASON_SUBJECT_TOKEN_INVALID
