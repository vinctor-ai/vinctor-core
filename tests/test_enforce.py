from datetime import UTC, datetime, timedelta

from vinctor_core import (
    BoundaryRegistrationInput,
    BoundaryRegistry,
    EnforceInput,
    Grant,
    evaluate_enforce,
    register_boundary,
)

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


def test_enforce_permits_matching_scope_without_boundary() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "permit"
    assert result.reason == "permitted"
    assert result.scope_attempted == "write:repo/feature/readme"
    assert result.scope_matched == "write:repo/feature/*"
    assert result.boundary is None


def test_enforce_permits_exact_scope_match() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(scopes=("write:repo/feature/readme",)),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "permit"
    assert result.scope_matched == "write:repo/feature/readme"


def test_scope_wildcard_does_not_match_wrong_action() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(scopes=("write:repo/feature/*",)),
            action="read",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "action_denied"


def test_scope_wildcard_does_not_match_sibling_prefix() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(scopes=("write:repo/feature/*",)),
            action="write",
            resource="repo/featurette/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "action_denied"


def test_non_terminal_resource_wildcard_is_invalid_grant_scope() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(scopes=("write:repo/*/readme",)),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_grant_scope"


def test_enforce_denies_scope_miss() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(scopes=("write:repo/feature/*",)),
            action="send",
            resource="email/external",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "action_denied"
    assert result.scope_matched is None


def test_enforce_denies_invalid_requested_action() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="wirte",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_action"
    assert result.scope_attempted == "wirte:repo/feature/readme"
    assert result.scope_matched is None


def test_enforce_denies_invalid_requested_resource() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="write",
            resource="repo/*",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_resource"
    assert result.scope_attempted == "write:repo/*"
    assert result.scope_matched is None


def test_enforce_denies_invalid_grant_scope() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(scopes=("write:repo/*/readme",)),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_grant_scope"
    assert result.scope_matched is None


def test_enforce_denies_invalid_grant_scope_even_when_another_scope_matches() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(
                scopes=("write:repo/feature/readme", "write:repo/*/readme")
            ),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "invalid_grant_scope"
    assert result.scope_matched is None


def test_enforce_denies_expired_grant_status() -> None:
    grant = active_grant(scopes=("write:repo/feature/*",))
    grant.status = "expired"

    result = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "grant_expired"


def test_enforce_denies_non_active_grant_status() -> None:
    grant = active_grant(scopes=("write:repo/feature/*",))
    grant.status = "suspended"

    result = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "grant_not_active"


def test_enforce_denies_revoked_grant_before_scope_match() -> None:
    grant = active_grant(scopes=("write:repo/feature/*",))
    grant.status = "revoked"

    result = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "grant_revoked"
    assert result.scope_matched is None


def test_enforce_denies_expired_grant() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=Grant(
                grant_id="grnt_main",
                grant_ref="grt_main",
                workspace_id="ws_main",
                agent_id="agent_release",
                scopes=("write:repo/feature/*",),
                status="active",
                expires_at=NOW - timedelta(seconds=1),
            ),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "grant_expired"


def test_enforce_with_valid_boundary_persists_boundary_context_in_result() -> None:
    registry = BoundaryRegistry()
    boundary = register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        now=NOW,
        boundary_id="bnd_valid",
    )

    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
            boundary_id="bnd_valid",
            boundary_registry=registry,
        )
    )

    assert result.decision == "permit"
    assert result.boundary == boundary


def test_enforce_with_unknown_boundary_denies_and_records_attempted_boundary_id() -> None:
    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="wirte",
            resource="repo/*",
            now=NOW,
            boundary_id="bnd_missing",
            boundary_registry=BoundaryRegistry(),
        )
    )

    assert result.decision == "deny"
    assert result.reason == "boundary_not_found"
    assert result.attempted_boundary_id == "bnd_missing"
    assert result.boundary is None
    assert result.scope_matched is None


def test_enforce_with_disabled_boundary_denies() -> None:
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="codex-local",
            runtime="codex",
            boundary_type="wrapper",
            status="disabled",
        ),
        now=NOW,
        boundary_id="bnd_disabled",
    )

    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
            boundary_id="bnd_disabled",
            boundary_registry=registry,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "boundary_inactive"


def test_enforce_with_other_workspace_boundary_denies() -> None:
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_other",
            name="langgraph-local",
            runtime="langgraph",
            boundary_type="middleware",
        ),
        now=NOW,
        boundary_id="bnd_other",
    )

    result = evaluate_enforce(
        EnforceInput(
            grant=active_grant(),
            action="write",
            resource="repo/feature/readme",
            now=NOW,
            boundary_id="bnd_other",
            boundary_registry=registry,
        )
    )

    assert result.decision == "deny"
    assert result.reason == "boundary_wrong_workspace"
