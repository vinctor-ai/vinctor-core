from datetime import UTC, datetime

from vinctor_core import (
    BoundaryRegistrationInput,
    BoundaryRegistry,
    disable_boundary,
    get_boundary_for_workspace,
    register_boundary,
)


def test_register_boundary_creates_active_fail_closed_boundary() -> None:
    registry = BoundaryRegistry()
    created_at = datetime(2026, 6, 10, tzinfo=UTC)

    boundary = register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
            mode="fail_closed",
        ),
        now=created_at,
        boundary_id="bnd_test",
    )

    assert boundary.boundary_id == "bnd_test"
    assert boundary.workspace_id == "ws_main"
    assert boundary.name == "claude-code-local"
    assert boundary.runtime == "claude-code"
    assert boundary.boundary_type == "pretooluse"
    assert boundary.mode == "fail_closed"
    assert boundary.status == "active"
    assert boundary.created_at == created_at
    assert boundary.updated_at == created_at
    assert registry.get("bnd_test") == boundary


def test_registry_lists_boundaries_by_workspace() -> None:
    registry = BoundaryRegistry()
    now = datetime(2026, 6, 10, tzinfo=UTC)

    first = register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="codex-local",
            runtime="codex",
            boundary_type="wrapper",
        ),
        now=now,
        boundary_id="bnd_first",
    )
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_other",
            name="hermes-local",
            runtime="hermes",
            boundary_type="adapter",
        ),
        now=now,
        boundary_id="bnd_other",
    )

    assert registry.list_for_workspace("ws_main") == [first]


def test_register_boundary_can_generate_boundary_id() -> None:
    registry = BoundaryRegistry()

    boundary = register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="custom-local",
            runtime="custom",
            boundary_type="wrapper",
        ),
    )

    assert boundary.boundary_id.startswith("bnd_")
    assert registry.get(boundary.boundary_id) == boundary


def test_register_boundary_rejects_non_fail_closed_mode() -> None:
    registry = BoundaryRegistry()

    try:
        register_boundary(
            registry,
            BoundaryRegistrationInput(
                workspace_id="ws_main",
                name="custom-local",
                runtime="custom",
                boundary_type="wrapper",
                mode="fail_open",  # type: ignore[arg-type]
            ),
        )
    except ValueError as exc:
        assert str(exc) == "boundary mode must be fail_closed"
    else:
        raise AssertionError("expected invalid boundary mode to fail")


def test_get_boundary_for_workspace_returns_none_for_wrong_workspace() -> None:
    registry = BoundaryRegistry()
    boundary = register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="claude-code-local",
            runtime="claude-code",
            boundary_type="pretooluse",
        ),
        boundary_id="bnd_main",
    )

    assert get_boundary_for_workspace(registry, "bnd_main", "ws_main") == boundary
    assert get_boundary_for_workspace(registry, "bnd_main", "ws_other") is None


def test_disable_boundary_marks_boundary_disabled_and_updates_timestamp() -> None:
    registry = BoundaryRegistry()
    created_at = datetime(2026, 6, 10, tzinfo=UTC)
    disabled_at = datetime(2026, 6, 11, tzinfo=UTC)
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="codex-local",
            runtime="codex",
            boundary_type="wrapper",
        ),
        now=created_at,
        boundary_id="bnd_disable",
    )

    disabled = disable_boundary(
        registry,
        boundary_id="bnd_disable",
        workspace_id="ws_main",
        now=disabled_at,
    )

    assert disabled is not None
    assert disabled.status == "disabled"
    assert disabled.created_at == created_at
    assert disabled.updated_at == disabled_at
    assert registry.get("bnd_disable") == disabled


def test_disable_boundary_returns_none_for_wrong_workspace() -> None:
    registry = BoundaryRegistry()
    register_boundary(
        registry,
        BoundaryRegistrationInput(
            workspace_id="ws_main",
            name="codex-local",
            runtime="codex",
            boundary_type="wrapper",
        ),
        boundary_id="bnd_disable",
    )

    assert (
        disable_boundary(
            registry,
            boundary_id="bnd_disable",
            workspace_id="ws_other",
        )
        is None
    )
