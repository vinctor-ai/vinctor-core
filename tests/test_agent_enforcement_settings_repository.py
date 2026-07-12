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


def test_sqlite_schema_records_version_6(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == (1, 2, 3, 4, 5, 6, 7, 8, 9, 10)


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
