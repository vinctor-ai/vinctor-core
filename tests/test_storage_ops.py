from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.models import GrantIssueRequest
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite
from vinctor_service.storage_ops import (
    _atomic_replace_sqlite,
    backup_sqlite,
    migrate_sqlite,
    read_schema_versions,
    reset_sqlite,
    restore_sqlite,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _sidecars(db_path: Path) -> tuple[Path, Path]:
    return (Path(f"{db_path}-wal"), Path(f"{db_path}-shm"))


def _plant_stale_sidecars(db_path: Path) -> None:
    wal_path, shm_path = _sidecars(db_path)
    wal_path.write_bytes(b"stale WAL from the database that will be replaced")
    shm_path.write_bytes(b"stale SHM from the database that will be replaced")


def _hold_live_wal(db_path: Path):
    conn = connect_sqlite(db_path)
    conn.execute("PRAGMA wal_autocheckpoint = 0")
    conn.execute("CREATE TABLE IF NOT EXISTS stale_writer (value INTEGER)")
    conn.execute("INSERT INTO stale_writer VALUES (1)")
    conn.commit()
    assert _sidecars(db_path)[0].exists()
    return conn


def _seed_db(db_path: Path) -> None:
    conn = connect_sqlite(db_path)
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
    assert result.schema_versions == tuple(range(1, 15))

    conn = connect_sqlite(output_path)
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


def test_backup_force_removes_stale_output_sidecars(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    output = tmp_path / "backup.sqlite"
    _seed_db(source)
    reset_sqlite(output)
    stale_connection = _hold_live_wal(output)

    try:
        backup_sqlite(source, output, force=True)
        assert all(not path.exists() for path in _sidecars(output))
    finally:
        stale_connection.close()

    conn = connect_sqlite(output)
    try:
        grant = SQLiteV1Service(
            conn, initialize_schema=False
        ).grant_repository.get_by_ref("grt_seed")
    finally:
        conn.close()
    assert grant is not None


def test_reset_clears_data_but_restores_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    result = reset_sqlite(db_path)

    assert result.schema_versions == tuple(range(1, 15))
    conn = connect_sqlite(db_path)
    try:
        service = SQLiteV1Service(conn, initialize_schema=False)
        assert service.grant_repository.get_by_ref("grt_seed") is None
        assert SQLiteLocalKeyRepository(conn).list_for_workspace("ws_demo") == ()
    finally:
        conn.close()


def test_reset_removes_stale_destination_wal_sidecars(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)
    stale_connection = _hold_live_wal(db_path)

    try:
        reset_sqlite(db_path)
        assert all(not path.exists() for path in _sidecars(db_path))
    finally:
        stale_connection.close()

    conn = connect_sqlite(db_path)
    try:
        assert (
            SQLiteV1Service(
                conn, initialize_schema=False
            ).grant_repository.get_by_ref("grt_seed")
            is None
        )
    finally:
        conn.close()


def test_reset_recreates_missing_db(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "vinctor.sqlite"

    result = reset_sqlite(db_path)

    assert db_path.exists()
    assert result.schema_versions == tuple(range(1, 15))


def test_read_schema_versions_missing_db_returns_none(tmp_path: Path) -> None:
    assert read_schema_versions(tmp_path / "missing.sqlite") is None


def test_read_schema_versions_existing_db(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    assert read_schema_versions(db_path) == tuple(range(1, 15))


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
    assert result.schema_versions == tuple(range(1, 15))
    conn = connect_sqlite(target)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_restore_removes_stale_destination_wal_sidecars(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    target = tmp_path / "vinctor.sqlite"
    _seed_db(source)
    reset_sqlite(target)
    stale_connection = _hold_live_wal(target)

    try:
        restore_sqlite(target, source)
        assert all(not path.exists() for path in _sidecars(target))
    finally:
        stale_connection.close()

    conn = connect_sqlite(target)
    try:
        grant = SQLiteV1Service(
            conn, initialize_schema=False
        ).grant_repository.get_by_ref("grt_seed")
    finally:
        conn.close()
    assert grant is not None


def test_atomic_replace_cleans_temp_sidecars_when_build_fails(tmp_path: Path) -> None:
    target = tmp_path / "vinctor.sqlite"
    created: list[Path] = []

    def failing_build(tmp_db: Path) -> tuple[int, ...]:
        created.append(tmp_db)
        _plant_stale_sidecars(tmp_db)
        raise RuntimeError("build failed")

    with pytest.raises(RuntimeError, match="build failed"):
        _atomic_replace_sqlite(target, failing_build)

    assert len(created) == 1
    assert not created[0].exists()
    assert all(not path.exists() for path in _sidecars(created[0]))


def test_restore_overwrites_existing_target(tmp_path: Path) -> None:
    source = tmp_path / "source.sqlite"
    target = tmp_path / "vinctor.sqlite"
    _seed_db(source)
    target.write_text("stale-not-a-db", encoding="utf-8")

    restore_sqlite(target, source)

    assert read_schema_versions(target) == tuple(range(1, 15))


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

    assert read_schema_versions(target) == tuple(range(1, 15))


def test_migrate_initializes_and_reports_versions(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "vinctor.sqlite"

    result = migrate_sqlite(db_path)

    assert db_path.exists()
    assert result.schema_versions == tuple(range(1, 15))


def test_migrate_is_idempotent_and_preserves_data(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    result = migrate_sqlite(db_path)

    assert result.schema_versions == tuple(range(1, 15))
    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_restore_preserves_live_db_when_snapshot_chain_is_broken(tmp_path: Path) -> None:
    live = tmp_path / "vinctor.sqlite"
    _seed_db(live)

    # A structurally valid snapshot whose audit chain has been tampered (the head
    # row's hash nulled). It passes the up-front schema check but must fail the
    # post-build chain verification, so the swap never happens.
    snapshot = tmp_path / "snapshot.sqlite"
    _seed_db(snapshot)
    scon = connect_sqlite(snapshot)
    scon.execute(
        "UPDATE audit_events SET row_hash = NULL "
        "WHERE seq = (SELECT MAX(seq) FROM audit_events)"
    )
    scon.commit()
    scon.close()

    with pytest.raises(ValueError, match="broken audit chain"):
        restore_sqlite(live, snapshot)

    # The failed restore never touched the live database (atomic swap-or-nothing):
    # the original grant is still present.
    assert live.exists()
    conn = connect_sqlite(live)
    try:
        grant = SQLiteV1Service(
            conn, initialize_schema=False
        ).grant_repository.get_by_ref("grt_seed")
    finally:
        conn.close()
    assert grant is not None
