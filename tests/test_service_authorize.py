from datetime import UTC, datetime, timedelta

from vinctor_core import (
    BoundaryRegistrationInput,
    BoundaryRegistry,
    Grant,
    register_boundary,
)
from vinctor_service import AuthorizationRequest, authorize_action

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def grant(
    grant_id: str,
    *,
    scopes: tuple[str, ...] = ("write:repo/feature/*",),
    status: str = "active",
) -> Grant:
    return Grant(
        grant_id=grant_id,
        grant_ref=f"grt_{grant_id}",
        workspace_id="ws_main",
        agent_id="agent_release",
        scopes=scopes,
        status=status,
        expires_at=NOW + timedelta(hours=1),
    )


def test_authorize_action_permits_matching_grant() -> None:
    response = authorize_action(
        AuthorizationRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            action="write",
            resource="repo/feature/readme",
        ),
        grants=(grant("match"),),
        now=NOW,
    )

    assert response.decision == "permit"
    assert response.reason == "permitted"
    assert response.grant_id == "match"
    assert response.grant_ref == "grt_match"
    assert response.scope_matched == "write:repo/feature/*"


def test_authorize_action_denies_without_applicable_grant() -> None:
    response = authorize_action(
        AuthorizationRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            action="write",
            resource="repo/feature/readme",
        ),
        grants=(grant("read_only", scopes=("read:repo/feature/*",)),),
        now=NOW,
    )

    assert response.decision == "deny"
    assert response.reason == "no_applicable_grant"
    assert response.grant_id is None
    assert response.grant_ref is None


def test_authorize_action_preserves_invalid_action_reason() -> None:
    response = authorize_action(
        AuthorizationRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            action="wirte",
            resource="repo/feature/readme",
        ),
        grants=(grant("match"),),
        now=NOW,
    )

    assert response.decision == "deny"
    assert response.reason == "invalid_action"
    assert response.scope_attempted == "wirte:repo/feature/readme"


def test_authorize_action_passes_boundary_registry_to_core() -> None:
    registry = BoundaryRegistry()
    register_boundary(
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

    response = authorize_action(
        AuthorizationRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            action="write",
            resource="repo/feature/readme",
            boundary_id="bnd_valid",
        ),
        grants=(grant("match"),),
        boundary_registry=registry,
        now=NOW,
    )

    assert response.decision == "permit"
    assert response.boundary_id == "bnd_valid"


def test_authorize_action_returns_boundary_denial() -> None:
    response = authorize_action(
        AuthorizationRequest(
            workspace_id="ws_main",
            agent_id="agent_release",
            action="write",
            resource="repo/feature/readme",
            boundary_id="bnd_missing",
        ),
        grants=(grant("match"),),
        boundary_registry=BoundaryRegistry(),
        now=NOW,
    )

    assert response.decision == "deny"
    assert response.reason == "boundary_not_found"
    assert response.boundary_id == "bnd_missing"
