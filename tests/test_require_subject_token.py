import sqlite3
from datetime import UTC, datetime, timedelta

from vinctor_core import Grant
from vinctor_core.audit import REASON_SUBJECT_TOKEN_REQUIRED
from vinctor_service import (
    InMemoryAuditWriter,
    InMemoryGrantRepository,
    InMemoryV1Service,
    SQLiteV1Service,
    V1DelegatedEnforceRequest,
)
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken
from vinctor_service.repositories import (
    InMemoryAgentEnforcementSettingsRepository,
    InMemorySubjectTokenRepository,
)
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


def _request(subject_token: str | None = None) -> V1DelegatedEnforceRequest:
    return V1DelegatedEnforceRequest(
        pep_id="pep_git_host",
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        action="write",
        resource="repo/feature/readme",
        subject_token=subject_token,
    )


def _valid_token_repo() -> tuple[str, InMemorySubjectTokenRepository]:
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
    )
    return raw, InMemorySubjectTokenRepository((token,))


def _hardened_settings() -> InMemoryAgentEnforcementSettingsRepository:
    settings = InMemoryAgentEnforcementSettingsRepository()
    settings.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_release", require_subject_token=True, now=NOW
    )
    return settings


def test_hardened_subject_without_token_denies_subject_token_required() -> None:
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        _request(subject_token=None),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        agent_enforcement_settings_repository=_hardened_settings(),
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events[0].reason_code == REASON_SUBJECT_TOKEN_REQUIRED


def test_hardened_subject_with_blank_token_denies_subject_token_required() -> None:
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        _request(subject_token="   "),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        agent_enforcement_settings_repository=_hardened_settings(),
    )
    assert response.status_code == 403
    assert response.error == "forbidden"
    assert response.decision is None
    assert audit.events[0].reason_code == REASON_SUBJECT_TOKEN_REQUIRED


def test_hardened_subject_with_valid_token_permits() -> None:
    audit = InMemoryAuditWriter()
    raw, repo = _valid_token_repo()
    response = delegated_enforce_v1_contract(
        _request(subject_token=raw),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
        subject_token_repository=repo,
        agent_enforcement_settings_repository=_hardened_settings(),
    )
    assert response.decision == "permit"
    assert audit.events[0].identity_proven is True


def test_unhardened_subject_without_token_permits() -> None:
    audit = InMemoryAuditWriter()
    response = delegated_enforce_v1_contract(
        _request(subject_token=None),
        grant_repository=InMemoryGrantRepository((_grant(),)),
        now=NOW,
        audit_writer=audit,
        pep_workspace_id="ws_main",
    )
    assert response.decision == "permit"


def _svc() -> InMemoryV1Service:
    return InMemoryV1Service(grants=(_grant(),))


def test_service_hardened_subject_denies_without_token() -> None:
    svc = _svc()
    svc.agent_enforcement_settings_repository.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_release", require_subject_token=True, now=NOW
    )
    r = svc.delegated_enforce(_request(subject_token=None), now=NOW, pep_workspace_id="ws_main")
    assert r.status_code == 403
    assert r.decision is None


def test_service_unhardened_subject_permits_without_token() -> None:
    svc = _svc()
    r = svc.delegated_enforce(_request(subject_token=None), now=NOW, pep_workspace_id="ws_main")
    assert r.decision == "permit"


def test_sqlite_hardened_subject_denies_without_token(tmp_path) -> None:
    # Pins the production (SQLite) wiring: the per-agent mandate must be consulted on
    # the SQLite delegated path too, not only InMemory.
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    service = SQLiteV1Service(conn)
    service.insert_grant(_grant())
    service.agent_enforcement_settings_repository.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_release", require_subject_token=True, now=NOW
    )
    r = service.delegated_enforce(
        _request(subject_token=None), now=NOW, pep_workspace_id="ws_main"
    )
    assert r.status_code == 403
    assert r.decision is None


def test_sqlite_unhardened_subject_permits_without_token(tmp_path) -> None:
    # Default-off regression on the real backend.
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    service = SQLiteV1Service(conn)
    service.insert_grant(_grant())
    r = service.delegated_enforce(
        _request(subject_token=None), now=NOW, pep_workspace_id="ws_main"
    )
    assert r.decision == "permit"


def test_ws_default_hardens_subject_without_own_row() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="", require_subject_token=True, now=NOW
    )
    assert repo.is_subject_token_required(workspace_id="ws_main", agent_id="agent_release") is True


def test_agent_row_overrides_ws_default_to_exempt() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="", require_subject_token=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_release", require_subject_token=False, now=NOW
    )
    assert repo.is_subject_token_required(workspace_id="ws_main", agent_id="agent_release") is False


def test_no_rows_is_not_required() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    assert (
        repo.get_require_subject_token_setting(workspace_id="ws_main", agent_id="agent_release")
        is None
    )
    assert repo.is_subject_token_required(workspace_id="ws_main", agent_id="agent_release") is False


def test_sqlite_settings_distinguishes_absent_from_explicit_false(tmp_path) -> None:
    # Resolution must distinguish absent (None) from an explicit False row, and must
    # not clobber the require_boundary column when upserting require_subject_token.
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    service = SQLiteV1Service(conn)
    repo = service.agent_enforcement_settings_repository
    assert (
        repo.get_require_subject_token_setting(workspace_id="ws_main", agent_id="agent_release")
        is None
    )
    repo.set_require_boundary(
        workspace_id="ws_main", agent_id="agent_release", require_boundary=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_release", require_subject_token=True, now=NOW
    )
    assert (
        repo.get_require_subject_token_setting(workspace_id="ws_main", agent_id="agent_release")
        is True
    )
    # require_boundary must survive the require_subject_token upsert (no clobber).
    assert (
        repo.get_require_boundary_setting(workspace_id="ws_main", agent_id="agent_release") is True
    )


def test_sqlite_require_pop_upsert_does_not_clobber_other_flags(tmp_path) -> None:
    # set_require_pop must not null out require_boundary / require_subject_token on the
    # same (workspace, agent) row.
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    service = SQLiteV1Service(conn)
    repo = service.agent_enforcement_settings_repository
    repo.set_require_boundary(
        workspace_id="ws_main", agent_id="agent_release", require_boundary=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws_main", agent_id="agent_release", require_subject_token=True, now=NOW
    )
    repo.set_require_pop(
        workspace_id="ws_main", agent_id="agent_release", require_pop=True, now=NOW
    )
    assert repo.get_require_pop_setting(workspace_id="ws_main", agent_id="agent_release") is True
    # The other two flags must survive the require_pop upsert (no clobber).
    assert (
        repo.get_require_boundary_setting(workspace_id="ws_main", agent_id="agent_release") is True
    )
    assert (
        repo.get_require_subject_token_setting(
            workspace_id="ws_main", agent_id="agent_release"
        )
        is True
    )
