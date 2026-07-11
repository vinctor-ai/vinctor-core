from datetime import UTC, datetime, timedelta

from vinctor_core import EnforceInput, Grant, evaluate_enforce
from vinctor_core.scope import is_valid_grant_scope, is_valid_requested_resource

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def active_grant(*, scopes: tuple[str, ...] = ("write:repo/feature/*",)) -> Grant:
    return Grant(
        grant_id="grnt_main",
        grant_ref="grt_main",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=scopes,
        status="active",
        expires_at=NOW + timedelta(hours=1),
    )


def test_v1_resource_paths_require_at_least_two_segments() -> None:
    assert is_valid_requested_resource("repo/feature")
    assert is_valid_grant_scope("write:repo/*")

    assert not is_valid_requested_resource("repo")
    assert not is_valid_grant_scope("write:repo")


def test_v1_requested_resources_cannot_use_grant_wildcards() -> None:
    assert is_valid_grant_scope("write:repo/feature/*")
    assert not is_valid_requested_resource("repo/feature/*")


def test_v1_invalid_action_remains_core_deny_for_service_mapping() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="push",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_action"
    assert result.scope_attempted == "push:repo/feature/readme"
