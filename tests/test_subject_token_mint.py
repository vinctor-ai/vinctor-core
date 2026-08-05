from datetime import UTC, datetime, timedelta

import pytest

from vinctor_core.audit import EVENT_ACCESS_REJECTED, REASON_AGENT_GRANT_MISMATCH
from vinctor_core.models import Grant
from vinctor_service import InMemoryV1Service
from vinctor_service.subject_tokens import mint_subject_token

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


def test_mint_unbound_stores_null_binding() -> None:
    svc = _svc(_grant())
    result = _mint(svc)
    token = svc.subject_token_repository.get_by_id(result.token_id)
    assert token.bound_action is None
    assert token.bound_resource is None


def test_mint_with_action_and_resource_stores_binding() -> None:
    svc = _svc(_grant())
    result = _mint(svc, bound_action="write", bound_resource="repo/feature/readme")
    assert result.status == "minted"
    token = svc.subject_token_repository.get_by_id(result.token_id)
    assert token.bound_action == "write"
    assert token.bound_resource == "repo/feature/readme"


def test_mint_with_only_action_raises_both_or_neither() -> None:
    svc = _svc(_grant())
    with pytest.raises(ValueError):
        _mint(svc, bound_action="write")


def test_mint_with_only_resource_raises_both_or_neither() -> None:
    svc = _svc(_grant())
    with pytest.raises(ValueError):
        _mint(svc, bound_resource="repo/feature/readme")


def test_mint_with_pop_returns_secret_and_stores_pop_required_token() -> None:
    svc = _svc(_grant())
    result = _mint(svc, pop=True)
    assert result.status == "minted"
    assert isinstance(result.pop_secret, str) and result.pop_secret != ""
    # the stored token is pop-required (gate is `pop_secret is not None`)
    token = svc.subject_token_repository.get_by_id(result.token_id)
    assert token.pop_secret is not None
    # the pop_secret never lands in audit
    assert result.pop_secret not in str(svc.audit_events[0].to_dict())


def test_mint_without_pop_returns_no_secret_and_non_pop_token() -> None:
    svc = _svc(_grant())
    result = _mint(svc)
    assert result.pop_secret is None
    token = svc.subject_token_repository.get_by_id(result.token_id)
    assert token.pop_secret is None


def test_forbidden_mint_records_operator_rejection_audit() -> None:
    # ADR 0008: the caller still gets only the generic forbidden, but the probe
    # is visible to the operator — mirroring the enforce/simulate mismatch paths.
    svc = _svc(_grant(agent_id="agent_other"))
    result = _mint(svc)
    assert result.status == "forbidden"
    assert [e.event_type for e in svc.audit_events] == [EVENT_ACCESS_REJECTED]
    event = svc.audit_events[0]
    assert event.decision == "deny"
    assert event.reason_code == REASON_AGENT_GRANT_MISMATCH
    # Attributed to the caller's own authenticated identity (key-derived in the
    # HTTP layer), never the grant's.
    assert event.workspace_id == "ws_main"
    assert event.agent_id == "agent_release"
    # The probed grant_ref is never echoed into the trail (existing convention).
    assert event.grant_id == ""
    assert event.grant_ref == ""
    assert "grt_main" not in str(event.to_dict())


def test_forbidden_mint_audit_is_identical_across_deny_causes() -> None:
    # No side-effect oracle: unknown grant_ref, foreign grant, revoked grant and
    # time-expired grant all record the SAME rejection event (modulo the random
    # event_id) — a probe cannot tell the cases apart from the audit side effects
    # any more than from the (identical) forbidden response.
    events = []

    svc = _svc(_grant())
    assert _mint(svc, grant_ref="grt_missing").status == "forbidden"
    events.append(svc.audit_events[0])

    for grant_over in (
        {"agent_id": "agent_other"},
        {"status": "revoked"},
        {"expires_at": NOW - timedelta(hours=1)},
    ):
        svc = _svc(_grant(**grant_over))
        assert _mint(svc).status == "forbidden"
        events.append(svc.audit_events[0])

    dicts = [{k: v for k, v in e.to_dict().items() if k != "event_id"} for e in events]
    assert all(d == dicts[0] for d in dicts[1:])


def test_forbidden_mint_audit_is_best_effort() -> None:
    # An audit-store failure never changes the caller-facing result: the mint is
    # still the same generic forbidden (the access is denied regardless).
    class Boom:
        def write(self, event) -> None:
            raise RuntimeError("audit store down")

    svc = _svc(_grant(agent_id="agent_other"))
    result = mint_subject_token(
        grant_repository=svc.grant_repository,
        subject_token_repository=svc.subject_token_repository,
        audit_writer=Boom(),
        workspace_id="ws_main",
        agent_id="agent_release",
        grant_ref="grt_main",
        audience="pep_git_host",
        ttl_seconds=300,
        now=NOW,
    )
    assert result.status == "forbidden"
