from datetime import UTC, datetime, timedelta

from vinctor_core import Grant, PolicyInput, evaluate_policy

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant(
    grant_id: str,
    *,
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    scopes: tuple[str, ...] = ("write:repo/feature/*",),
    status: str = "active",
) -> Grant:
    return Grant(
        grant_id=grant_id,
        grant_ref=f"grt_{grant_id}",
        workspace_id=workspace_id,
        agent_id=agent_id,
        scopes=scopes,
        status=status,
        expires_at=NOW + timedelta(hours=1),
    )


def test_policy_permits_first_applicable_grant_in_input_order() -> None:
    result = evaluate_policy(
        PolicyInput(
            workspace_id="ws_main",
            agent_id="agent_release",
            grants=(
                grant("miss", scopes=("read:repo/feature/*",)),
                grant("match", scopes=("write:repo/feature/*",)),
                grant("later_match", scopes=("write:repo/*",)),
            ),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "permit"
    assert result.reason == "permitted"
    assert result.grant_id == "match"
    assert result.enforce_result is not None
    assert result.enforce_result.scope_matched == "write:repo/feature/*"


def test_policy_ignores_grants_for_other_workspace_or_agent() -> None:
    result = evaluate_policy(
        PolicyInput(
            workspace_id="ws_main",
            agent_id="agent_release",
            grants=(
                grant("other_workspace", workspace_id="ws_other"),
                grant("other_agent", agent_id="agent_other"),
            ),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "no_applicable_grant"
    assert result.grant_id is None
    assert result.enforce_result is None


def test_policy_denies_when_candidate_grants_do_not_permit_action() -> None:
    result = evaluate_policy(
        PolicyInput(
            workspace_id="ws_main",
            agent_id="agent_release",
            grants=(
                grant("read_only", scopes=("read:repo/feature/*",)),
                grant("suspended", status="suspended"),
            ),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "no_applicable_grant"
    assert result.grant_id is None
    assert result.enforce_result is None


def test_policy_returns_validation_denial_before_grant_selection() -> None:
    result = evaluate_policy(
        PolicyInput(
            workspace_id="ws_main",
            agent_id="agent_release",
            grants=(grant("match"),),
            action="wirte",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_action"
    assert result.grant_id is None
    assert result.enforce_result is None
    assert result.scope_attempted == "wirte:repo/feature/readme"


def test_policy_preserves_invalid_grant_scope_denial() -> None:
    result = evaluate_policy(
        PolicyInput(
            workspace_id="ws_main",
            agent_id="agent_release",
            grants=(
                grant("bad_scope", scopes=("write:repo/*/readme",)),
                grant("later_match", scopes=("write:repo/feature/*",)),
            ),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_grant_scope"
    assert result.grant_id == "bad_scope"
    assert result.enforce_result is not None


def test_policy_preserves_boundary_denial() -> None:
    result = evaluate_policy(
        PolicyInput(
            workspace_id="ws_main",
            agent_id="agent_release",
            grants=(grant("match"),),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
            boundary_id="bnd_missing",
        )
    )

    assert result.decision == "deny"
    assert result.reason == "boundary_not_found"
    assert result.grant_id == "match"
    assert result.enforce_result is not None
    assert result.enforce_result.attempted_boundary_id == "bnd_missing"
