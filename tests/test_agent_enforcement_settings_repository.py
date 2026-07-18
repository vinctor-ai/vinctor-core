
from datetime import UTC, datetime

from vinctor_service import (
    InMemoryAgentEnforcementSettingsRepository,
    SQLiteAgentEnforcementSettingsRepository,
)
from vinctor_service.control_audit import ControlPlaneAuditor
from vinctor_service.sqlite import (
    SQLiteAuditWriter,
    get_sqlite_schema_versions,
    init_sqlite_schema,
)
from vinctor_service.sqlite_txn import connect_sqlite


def _sqlite_repo(conn) -> SQLiteAgentEnforcementSettingsRepository:
    return SQLiteAgentEnforcementSettingsRepository(
        conn, ControlPlaneAuditor(SQLiteAuditWriter(conn))
    )

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def test_in_memory_default_false_and_set_get() -> None:
    repo = InMemoryAgentEnforcementSettingsRepository()
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=True, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is True
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False


def test_sqlite_default_false_and_round_trip(tmp_path) -> None:
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is False
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=True, now=NOW)
    assert repo.get_require_boundary(workspace_id="ws", agent_id="a") is True


def test_sqlite_schema_records_latest_version(tmp_path) -> None:
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == tuple(range(1, 16))


def test_unrelated_agent_setting_does_not_override_workspace_boundary(tmp_path) -> None:
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    repo.set_require_boundary(
        workspace_id="ws", agent_id="", require_boundary=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws", agent_id="a", require_subject_token=True, now=NOW
    )
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True


def test_boundary_override_presence_migration_preserves_existing_rows(tmp_path) -> None:
    # Fail-closed migration semantics: a migrated require_boundary=1 row keeps
    # reading as an explicit override; a require_boundary=0 row becomes UNSET
    # (None) rather than an explicit false, so it can no longer silently exempt
    # the agent from a workspace-wide mandate (schema v13 realignment).
    conn = connect_sqlite(tmp_path / "v.sqlite")
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
    repo = _sqlite_repo(conn)
    assert repo.get_require_boundary_setting(
        workspace_id="ws", agent_id="enabled"
    ) is True
    assert repo.get_require_boundary_setting(
        workspace_id="ws", agent_id="disabled"
    ) is None


def test_migrated_db_new_subject_token_row_does_not_override_workspace_boundary(
    tmp_path,
) -> None:
    # Upgrade path: an old-schema table (no require_boundary_set) is migrated,
    # so the added column defaults to 1. A row created afterwards purely via
    # set_require_subject_token must NOT be read as an explicit boundary
    # override, or it would silently exempt the agent from a workspace-wide
    # require_boundary. Regression for the fresh-vs-migrated divergence.
    conn = connect_sqlite(tmp_path / "v.sqlite")
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
    repo = _sqlite_repo(conn)
    repo.set_require_boundary(workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    repo.set_require_subject_token(
        workspace_id="ws", agent_id="a", require_subject_token=True, now=NOW
    )
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True


def test_migrated_db_new_pop_row_does_not_override_workspace_boundary(tmp_path) -> None:
    # Same fresh-vs-migrated divergence, reached through set_require_pop.
    conn = connect_sqlite(tmp_path / "v.sqlite")
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
    repo = _sqlite_repo(conn)
    repo.set_require_boundary(workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    repo.set_require_pop(workspace_id="ws", agent_id="a", require_pop=True, now=NOW)
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True


def test_unrelated_setting_does_not_drop_workspace_require_subject_token(tmp_path) -> None:
    # SECURITY: an unrelated agent-level setting must NOT silently disable a
    # workspace-wide require_subject_token mandate. The shared settings row means
    # "a row exists" was misread as "the agent explicitly set require_subject_token
    # = its default false", overriding the workspace true. Presence-bit gated.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    repo.set_require_subject_token(
        workspace_id="ws", agent_id="", require_subject_token=True, now=NOW
    )
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    assert repo.is_subject_token_required(workspace_id="ws", agent_id="a") is True


def test_unrelated_setting_does_not_drop_workspace_require_pop(tmp_path) -> None:
    # SECURITY: same bypass for the require_pop mandate.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    repo.set_require_pop(workspace_id="ws", agent_id="", require_pop=True, now=NOW)
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is True


def test_explicit_agent_require_subject_token_false_still_exempts(tmp_path) -> None:
    # The presence bit must still let an operator EXPLICITLY exempt an agent.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    repo.set_require_subject_token(
        workspace_id="ws", agent_id="", require_subject_token=True, now=NOW
    )
    repo.set_require_subject_token(
        workspace_id="ws", agent_id="a", require_subject_token=False, now=NOW
    )
    assert repo.is_subject_token_required(workspace_id="ws", agent_id="a") is False


OLD_SCHEMA_WITHOUT_PRESENCE_BITS = """
    CREATE TABLE agent_enforcement_settings (
        workspace_id TEXT NOT NULL,
        agent_id TEXT NOT NULL,
        require_boundary INTEGER NOT NULL DEFAULT 0,
        require_subject_token INTEGER NOT NULL DEFAULT 0,
        require_pop INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (workspace_id, agent_id)
    );
"""


def test_presence_migration_keeps_existing_subject_token_mandate(tmp_path) -> None:
    # Fail-closed migration: an existing require_subject_token=1 row must be
    # marked "set" and keep reading as required after the *_set columns land.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    conn.executescript(
        OLD_SCHEMA_WITHOUT_PRESENCE_BITS
        + """
        INSERT INTO agent_enforcement_settings
            (workspace_id, agent_id, require_subject_token, updated_at)
        VALUES ('ws', 'a', 1, '2026-01-01T00:00:00+00:00');
        """
    )
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    assert repo.get_require_subject_token_setting(workspace_id="ws", agent_id="a") is True
    assert repo.is_subject_token_required(workspace_id="ws", agent_id="a") is True


def test_presence_migration_unrelated_row_keeps_workspace_token_and_pop_mandates(
    tmp_path,
) -> None:
    # SECURITY: a migrated row that only ever carried an unrelated mandate
    # (require_boundary) must NOT read as explicit require_subject_token /
    # require_pop = false, which would drop the workspace-wide mandates.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    conn.executescript(
        OLD_SCHEMA_WITHOUT_PRESENCE_BITS
        + """
        INSERT INTO agent_enforcement_settings
            (workspace_id, agent_id, require_boundary, require_subject_token,
             require_pop, updated_at)
        VALUES ('ws', '', 0, 1, 1, '2026-01-01T00:00:00+00:00'),
               ('ws', 'a', 1, 0, 0, '2026-01-01T00:00:00+00:00');
        """
    )
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    assert repo.is_subject_token_required(workspace_id="ws", agent_id="a") is True
    assert repo.is_pop_required(workspace_id="ws", agent_id="a") is True


def test_boundary_realignment_unsets_subject_token_only_row_override(tmp_path) -> None:
    # SECURITY: the original require_boundary_set migration defaulted migrated
    # rows to 1 (preserve-all), so a subject-token-only row read as an explicit
    # require_boundary=false override of the workspace mandate. The one-time
    # version-gated realignment (schema v13) marks boundary "set" only where
    # require_boundary is already true, so the workspace mandate applies again.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    conn.executescript(
        OLD_SCHEMA_WITHOUT_PRESENCE_BITS
        + """
        INSERT INTO agent_enforcement_settings
            (workspace_id, agent_id, require_boundary, require_subject_token,
             require_pop, updated_at)
        VALUES ('ws', '', 1, 0, 0, '2026-01-01T00:00:00+00:00'),
               ('ws', 'a', 0, 1, 0, '2026-01-01T00:00:00+00:00');
        """
    )
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is True


def test_boundary_realignment_is_one_time_and_version_gated(tmp_path) -> None:
    # After the v13 realignment has run, an operator's explicit
    # require_boundary=false exemption must survive a later re-init.
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
    repo.set_require_boundary(workspace_id="ws", agent_id="", require_boundary=True, now=NOW)
    repo.set_require_boundary(workspace_id="ws", agent_id="a", require_boundary=False, now=NOW)
    init_sqlite_schema(conn)
    assert repo.is_boundary_required(workspace_id="ws", agent_id="a") is False


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
    conn = connect_sqlite(tmp_path / "v.sqlite")
    init_sqlite_schema(conn)
    repo = _sqlite_repo(conn)
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
