import sqlite3
from datetime import UTC, datetime

from vinctor_service import (
    InMemoryAgentEnforcementSettingsRepository,
    SQLiteAgentEnforcementSettingsRepository,
)
from vinctor_service.sqlite import get_sqlite_schema_versions, init_sqlite_schema

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def test_in_memory_default_false_and_set_get() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=True, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is True
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False


def test_sqlite_default_false_and_round_trip(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteAgentEnforcementSettingsRepository(conn)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=True, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is True


def test_sqlite_schema_records_latest_version(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == tuple(range(1, 13))


def test_unrelated_agent_setting_does_not_override_workspace_boundary(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteAgentEnforcementSettingsRepository(conn)
    repo.set_require_boundary(
        workspace_id="ws", agent_id="", require_boundary=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws", agent_id="a", require_subject_token=True, now=NOW
    )
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True


def test_boundary_override_presence_migration_preserves_existing_rows(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    conn.executescript(
        """
        CREATE TABLE agent_enforcement_settings (
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            require_boundary INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (workspace_id, agent_id)
        );
        INSERT INTO agent_enforcement_settings
            (workspace_id, agent_id, require_boundary, updated_at)
        VALUES ('ws', 'enabled', 1, '2026-01-01T00:00:00+00:00'),
               ('ws', 'disabled', 0, '2026-01-01T00:00:00+00:00');
        """
    )
    init_sqlite_schema(conn)
    repo = SQLiteAgentEnforcementSettingsRepository(conn)
    assert repo.get_require_boundary_setting(
        workspace_id="ws", agent_id="enabled"
    ) is True
    assert repo.get_require_boundary_setting(
        workspace_id="ws", agent_id="disabled"
    ) is False


def test_migrated_db_new_subject_token_row_does_not_override_workspace_boundary(
    tmp_path,
) -> None:
    # Upgrade path: an old-schema table (no require_boundary_set) is migrated,
    # so the added column defaults to 1. A row created afterwards purely via
    # set_require_subject_token must NOT be read as an explicit boundary
    # override, or it would silently exempt the agent from a workspace-wide
    # require_boundary. Regression for the fresh-vs-migrated divergence.
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    conn.executescript(
        """
        CREATE TABLE agent_enforcement_settings (
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            require_boundary INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (workspace_id, agent_id)
        );
        """
    )
    init_sqlite_schema(conn)
    repo = SQLiteAgentEnforcementSettingsRepository(conn)
    repo.set_require_boundary(workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    repo.set_require_subject_token(
        workspace_id="ws", agent_id="a", require_subject_token=True, now=NOW
    )
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True


def test_migrated_db_new_pop_row_does_not_override_workspace_boundary(tmp_path) -> None:
    # Same fresh-vs-migrated divergence, reached through set_require_pop.
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    conn.executescript(
        """
        CREATE TABLE agent_enforcement_settings (
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            require_boundary INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (workspace_id, agent_id)
        );
        """
    )
    init_sqlite_schema(conn)
    repo = SQLiteAgentEnforcementSettingsRepository(conn)
    repo.set_require_boundary(workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    repo.set_require_pop(workspace_id="ws", agent_id="a", require_pop=True, now=NOW)
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True


def test_in_memory_require_pop_default_false_and_set_get() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    assert repo.get_require_pop_setting(workspace_id="ws", agent_id="a") is None
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is False
    repo.set_require_pop(workspace_id="ws", agent_id="a", require_pop=True, now=NOW)
    assert repo.get_require_pop_setting(workspace_id="ws", agent_id="a") is True
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is True
    repo.set_require_pop(workspace_id="ws", agent_id="a", require_pop=False, now=NOW)
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is False


def test_sqlite_require_pop_default_false_and_round_trip(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = SQLiteAgentEnforcementSettingsRepository(conn)
    assert repo.get_require_pop_setting(workspace_id="ws", agent_id="a") is None
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is False
    repo.set_require_pop(workspace_id="ws", agent_id="a", require_pop=True, now=NOW)
    assert repo.get_require_pop_setting(workspace_id="ws", agent_id="a") is True
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is True


def test_require_pop_ws_default_falls_through_when_agent_row_absent() -> None:
    # Mirrors is_subject_token_required: agent -> workspace("") -> False fallback.
    repo = InMemoryAgentEnforcementSettingsRepository()
    repo.set_require_pop(workspace_id="ws", agent_id="", require_pop=True, now=NOW)
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is True


def test_require_pop_agent_row_overrides_ws_default_to_exempt() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    repo.set_require_pop(workspace_id="ws", agent_id="", require_pop=True, now=NOW)
    repo.set_require_pop(workspace_id="ws", agent_id="a", require_pop=False, now=NOW)
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is False
