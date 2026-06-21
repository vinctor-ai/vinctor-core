from datetime import UTC, datetime, timedelta

from vinctor_core.models import Grant
from vinctor_service import AgentIdentity, InMemoryV1Service, handle_v1_tokens_http

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _grant(agent_id="agent_release") -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id=agent_id,
        scopes=("write:repo/feature/*",),
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def _identities():
    return {
        "agent_key_main": AgentIdentity(workspace_id="ws_main", agent_id="agent_release")
    }


def _call(svc, *, headers=None, body=None, max_ttl=None):
    kwargs = dict(
        headers={"X-Agent-Key": "agent_key_main"} if headers is None else headers,
        body={"grant_ref": "grt_main", "audience": "pep_git_host", "ttl_seconds": 300}
        if body is None
        else body,
        agent_identities=_identities(),
        service=svc,
        now=NOW,
    )
    if max_ttl is not None:
        kwargs["max_ttl"] = max_ttl
    return handle_v1_tokens_http(**kwargs)


def test_mint_returns_201_with_token() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(svc)
    assert r.status_code == 201
    assert r.body["token"].startswith("vat_")
    assert r.body["token_id"].startswith("vtk_")
    assert "expires_at" in r.body


def test_mint_requires_agent_key_and_records_auth_failure() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(svc, headers={})
    assert r.status_code == 401
    assert r.body["error"] == "authentication_required"
    assert [e.event_type for e in svc.audit_events] == ["auth_failed"]


def test_mint_rejects_non_positive_ttl_with_400() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(
        svc,
        body={"grant_ref": "grt_main", "audience": "pep_git_host", "ttl_seconds": 0},
    )
    assert r.status_code == 400
    assert r.body["error"] == "invalid_request"


def test_mint_rejects_ttl_over_max_with_400() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(
        svc,
        body={
            "grant_ref": "grt_main",
            "audience": "pep_git_host",
            "ttl_seconds": 999_999,
        },
    )
    assert r.status_code == 400


def test_mint_rejects_ttl_over_lowered_max_ceiling_with_400() -> None:
    svc = InMemoryV1Service(grants=(_grant(),))
    r = _call(
        svc,
        body={"grant_ref": "grt_main", "audience": "pep_git_host", "ttl_seconds": 200},
        max_ttl=100,
    )
    assert r.status_code == 400


def test_mint_other_agents_grant_is_403_no_leak() -> None:
    svc = InMemoryV1Service(grants=(_grant(agent_id="agent_other"),))
    r = _call(svc)
    assert r.status_code == 403
    assert r.body["error"] == "forbidden"
    assert "grt_main" not in str(r.body)
