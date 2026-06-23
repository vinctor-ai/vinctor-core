from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.models import GrantIssueRequest
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.storage_ops import (
    backup_sqlite,
    migrate_sqlite,
    read_schema_versions,
    reset_sqlite,
    restore_sqlite,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _seed_db(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
    try:
        service = SQLiteV1Service(conn)
        service.set_agent_issuable_scope_bounds(
            workspace_id="ws_demo",
            agent_id="agent_runner",
            scopes=("execute:ci/test",),
            now=NOW,
        )
        service.issue_grant(
            GrantIssueRequest(
                workspace_id="ws_demo",
                target_agent_id="agent_runner",
                requested_scopes=("execute:ci/test",),
                ttl_seconds=3600,
                grant_ref="grt_seed",
            ),
            now=NOW,
        )
        SQLiteLocalKeyRepository(conn).create_workspace_key(
            workspace_id="ws_demo",
            raw_key="wsk_demo",
            now=NOW,
        )
    finally:
        conn.close()


def test_backup_sqlite_creates_queryable_copy(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    output_path = tmp_path / "backups" / "vinctor.backup.sqlite"
    _seed_db(db_path)

    result = backup_sqlite(db_path, output_path)

    assert result.output_path == output_path
    assert result.bytes > 0
    assert result.schema_versions == (1, 2, 3, 4, 5, 6)

    conn = sqlite3.connect(output_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None
    assert grant.workspace_id == "ws_demo"


def test_backup_refuses_existing_output_without_force(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    output_path = tmp_path / "vinctor.backup.sqlite"
    _seed_db(db_path)
    output_path.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError):
        backup_sqlite(db_path, output_path)

    result = backup_sqlite(db_path, output_path, force=True)
    assert result.bytes > 0


def test_backup_missing_source_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        backup_sqlite(tmp_path / "missing.sqlite", tmp_path / "out.sqlite")


def test_reset_clears_data_but_restores_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    result = reset_sqlite(db_path)

    assert result.schema_versions == (1, 2, 3, 4, 5, 6)
    conn = sqlite3.connect(db_path)
    try:
        service = SQLiteV1Service(conn, initialize_schema=False)
        assert service.grant_repository.get_by_ref("grt_seed") is None
        assert SQLiteLocalKeyRepository(conn).list_for_workspace("ws_demo") == ()
    finally:
        conn.close()


def test_reset_recreates_missing_db(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "vinctor.sqlite"

    result = reset_sqlite(db_path)

    assert db_path.exists()
    assert result.schema_versions == (1, 2, 3, 4, 5, 6)


def test_read_schema_versions_missing_db_returns_none(tmp_path: Path) -> None:
    assert read_schema_versions(tmp_path / "missing.sqlite") is None


def test_read_schema_versions_existing_db(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    assert read_schema_versions(db_path) == (1, 2, 3, 4, 5, 6)


def test_read_schema_versions_does_not_create_db(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"

    read_schema_versions(db_path)

    assert not db_path.exists()


def test_restore_replaces_db_from_snapshot(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    target = tmp_path / "nested" / "vinctor.sqlite"
    _seed_db(source)

    result = restore_sqlite(target, source)

    assert result.input_path == source
    assert result.schema_versions == (1, 2, 3, 4, 5, 6)
    conn = sqlite3.connect(target)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_restore_overwrites_existing_target(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    target = tmp_path / "vinctor.sqlite"
    _seed_db(source)
    target.write_text("stale-not-a-db", encoding="utf-8")

    restore_sqlite(target, source)

    assert read_schema_versions(target) == (1, 2, 3, 4, 5, 6)


def test_restore_missing_input_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        restore_sqlite(tmp_path / "db.sqlite", tmp_path / "missing.sqlite")


def test_restore_invalid_snapshot_raises_and_keeps_target(tmp_path: Path) -> None:
    source = tmp_path / "garbage.sqlite"
    source.write_text("not a database", encoding="utf-8")
    target = tmp_path / "vinctor.sqlite"
    _seed_db(target)

    with pytest.raises(ValueError):
        restore_sqlite(target, source)

    assert read_schema_versions(target) == (1, 2, 3, 4, 5, 6)


def test_migrate_initializes_and_reports_versions(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "vinctor.sqlite"

    result = migrate_sqlite(db_path)

    assert db_path.exists()
    assert result.schema_versions == (1, 2, 3, 4, 5, 6)


def test_migrate_is_idempotent_and_preserves_data(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    result = migrate_sqlite(db_path)

    assert result.schema_versions == (1, 2, 3, 4, 5, 6)
    conn = sqlite3.connect(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None
