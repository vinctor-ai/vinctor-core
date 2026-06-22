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


def test_sqlite_schema_records_version_4(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == (1, 2, 3, 4)
