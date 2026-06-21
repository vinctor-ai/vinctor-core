from datetime import UTC, datetime, timedelta

from vinctor_core.models import Grant
from vinctor_service import InMemoryV1Service

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _grant(
    *, agent_id="agent_release", status="active", expires_at=NOW + timedelta(hours=1)
) -> Grant:
    return Grant(
        grant_id="grnt_main", grant_ref="grt_main", workspace_id="ws_main",
        agent_id=agent_id, scopes=("write:repo/feature/*",), status=status,
        expires_at=expires_at,
    )


def _svc(grant: Grant) -> InMemoryV1Service:
    return InMemoryV1Service(grants=(grant,))


def _mint(svc, **over):
    kwargs = dict(workspace_id="ws_main", agent_id="agent_release",
                  grant_ref="grt_main", audience="pep_git_host",
                  ttl_seconds=300, now=NOW)
    kwargs.update(over)
    return svc.mint_subject_token(**kwargs)


def test_mint_for_owned_valid_grant_returns_token() -> None:
    svc = _svc(_grant())
    result = _mint(svc)
    assert result.status == "minted"
    assert result.token.startswith("vat_")
    assert result.token_id.startswith("vtk_")
    assert result.expires_at == NOW + timedelta(seconds=300)
    # a subject_token_minted audit row is written, never the raw token
    assert [e.event_type for e in svc.audit_events] == ["subject_token_minted"]
    assert result.token not in str(svc.audit_events[0].to_dict())


def test_mint_for_other_agents_grant_is_forbidden() -> None:
    svc = _svc(_grant(agent_id="agent_other"))
    assert _mint(svc).status == "forbidden"


def test_mint_for_revoked_grant_is_forbidden() -> None:
    svc = _svc(_grant(status="revoked"))
    assert _mint(svc).status == "forbidden"


def test_mint_for_time_expired_but_status_active_grant_is_forbidden() -> None:
    svc = _svc(_grant(expires_at=NOW - timedelta(hours=1)))
    assert _mint(svc).status == "forbidden"


def test_mint_clamps_expiry_to_grant_expiry() -> None:
    svc = _svc(_grant(expires_at=NOW + timedelta(seconds=60)))
    assert _mint(svc, ttl_seconds=300).expires_at == NOW + timedelta(seconds=60)
