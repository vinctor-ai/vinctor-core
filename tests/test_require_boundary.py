import sqlite3
from datetime import UTC, datetime, timedelta

from vinctor_core.enforce import evaluate_enforce
from vinctor_core.models import EnforceInput, Grant
from vinctor_service import (
    InMemoryV1Service,
    SQLiteV1Service,
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _grant() -> Grant:
    return Grant(
        grant_id="g", grant_ref="grt", workspace_id="ws", agent_id="a",
        scopes=("write:repo/x/*",), status="active", expires_at=NOW + timedelta(hours=1),
    )


def _input(**over) -> EnforceInput:
    kwargs = dict(grant=_grant(), action="write", resource="repo/x/y", now=NOW)
    kwargs.update(over)
    return EnforceInput(**kwargs)


def test_require_boundary_absent_denies_boundary_required() -> None:
    d = evaluate_enforce(_input(require_boundary=True))
    assert d.decision == "deny"
    assert d.reason == "boundary_required"
    assert d.attempted_boundary_id is None


def test_require_boundary_off_absent_permits() -> None:
    d = evaluate_enforce(_input())
    assert d.decision == "permit"


def test_require_boundary_on_empty_header_still_boundary_not_found() -> None:
    # Empty/whitespace header is NOT absent — it must keep denying boundary_not_found,
    # not flip to boundary_required (and definitely not permit).
    d = evaluate_enforce(_input(boundary_id="", require_boundary=True))
    assert d.decision == "deny"
    assert d.reason == "boundary_not_found"


def test_require_boundary_off_empty_header_denies_boundary_not_found() -> None:
    # Regression: empty header on the default-off path keeps denying (was untested).
    d = evaluate_enforce(_input(boundary_id=""))
    assert d.decision == "deny"
    assert d.reason == "boundary_not_found"


def _svc() -> InMemoryV1Service:
    return InMemoryV1Service(grants=(_grant(),))


def _harden(svc: InMemoryV1Service) -> None:
    svc.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws", agent_id="a", require_boundary=True, now=NOW
    )


def test_direct_enforce_hardened_agent_denies_without_boundary() -> None:
    svc = _svc()
    _harden(svc)
    r = svc.enforce(
        V1EnforceRequest(
            workspace_id="ws",
            agent_id="a",
            grant_ref="grt",
            action="write",
            resource="repo/x/y",
        ),
        now=NOW,
    )
    assert r.status_code == 403
    assert r.decision == "deny"


def test_direct_enforce_unhardened_agent_permits_without_boundary() -> None:
    svc = _svc()  # no flag
    r = svc.enforce(
        V1EnforceRequest(
            workspace_id="ws",
            agent_id="a",
            grant_ref="grt",
            action="write",
            resource="repo/x/y",
        ),
        now=NOW,
    )
    assert r.decision == "permit"


def test_delegated_enforce_hardened_subject_denies_without_boundary() -> None:
    svc = _svc()
    _harden(svc)
    r = svc.delegated_enforce(
        V1DelegatedEnforceRequest(
            pep_id="pep",
            workspace_id="ws",
            agent_id="a",
            grant_ref="grt",
            action="write",
            resource="repo/x/y",
            pep_workspace_id="ws",
        ),
        now=NOW,
    )
    assert r.status_code == 403
    assert r.decision == "deny"


def test_delegated_enforce_unhardened_subject_permits_without_boundary() -> None:
    svc = _svc()  # no flag
    r = svc.delegated_enforce(
        V1DelegatedEnforceRequest(
            pep_id="pep",
            workspace_id="ws",
            agent_id="a",
            grant_ref="grt",
            action="write",
            resource="repo/x/y",
            pep_workspace_id="ws",
        ),
        now=NOW,
    )
    assert r.decision == "permit"


def test_sqlite_hardened_agent_denies_without_boundary(tmp_path) -> None:
    # Pins the production (SQLite) wiring: the per-agent flag must be consulted on
    # the SQLite enforce path too, not only InMemory (a dropped repo there would be
    # a silent fail-open the InMemory tests cannot catch).
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    service = SQLiteV1Service(conn)
    service.insert_grant(_grant())
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws", agent_id="a", require_boundary=True, now=NOW
    )
    request = V1EnforceRequest(
        workspace_id="ws", agent_id="a", grant_ref="grt", action="write", resource="repo/x/y"
    )
    r = service.enforce(request, now=NOW)
    assert r.status_code == 403
    assert r.decision == "deny"


def test_sqlite_unhardened_agent_permits_without_boundary(tmp_path) -> None:
    # Default-off regression on the real backend.
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    service = SQLiteV1Service(conn)
    service.insert_grant(_grant())
    request = V1EnforceRequest(
        workspace_id="ws", agent_id="a", grant_ref="grt", action="write", resource="repo/x/y"
    )
    r = service.enforce(request, now=NOW)
    assert r.decision == "permit"
