from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.models import GrantIssueRequest
from vinctor_service.sqlite import (
    SQLITE_SCHEMA_VERSION_MAX,
    SchemaVersionError,
    SQLiteV1Service,
    get_sqlite_schema_versions,
    init_sqlite_schema,
)
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
    assert result.schema_versions == tuple(range(1, 17))

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

    assert result.schema_versions == tuple(range(1, 17))
    conn = connect_sqlite(db_path)
    try:
        service = SQLiteV1Service(conn, initialize_schema=False)
        assert service.grant_repository.get_by_ref("grt_seed") is None
        assert SQLiteLocalKeyRepository(conn).list_for_workspace("ws_demo") == ()
    finally:
        conn.close()


def test_reset_refuses_open_vinctor_handle_then_removes_stale_sidecars(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)
    stale_connection = _hold_live_wal(db_path)

    try:
        with pytest.raises(RuntimeError, match="database is in use"):
            reset_sqlite(db_path)
    finally:
        stale_connection.close()

    reset_sqlite(db_path)
    assert all(not path.exists() for path in _sidecars(db_path))

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
    assert result.schema_versions == tuple(range(1, 17))


def test_read_schema_versions_missing_db_returns_none(tmp_path: Path) -> None:
    assert read_schema_versions(tmp_path / "missing.sqlite") is None


def test_read_schema_versions_existing_db(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    assert read_schema_versions(db_path) == tuple(range(1, 17))


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
    assert result.schema_versions == tuple(range(1, 17))
    conn = connect_sqlite(target)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_restore_refuses_open_vinctor_handle_then_removes_stale_sidecars(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.sqlite"
    target = tmp_path / "vinctor.sqlite"
    _seed_db(source)
    reset_sqlite(target)
    stale_connection = _hold_live_wal(target)

    try:
        with pytest.raises(RuntimeError, match="database is in use"):
            restore_sqlite(target, source)
    finally:
        stale_connection.close()

    restore_sqlite(target, source)
    assert all(not path.exists() for path in _sidecars(target))

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

    assert read_schema_versions(target) == tuple(range(1, 17))


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

    assert read_schema_versions(target) == tuple(range(1, 17))


def test_migrate_initializes_and_reports_versions(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "vinctor.sqlite"

    result = migrate_sqlite(db_path)

    assert db_path.exists()
    assert result.schema_versions == tuple(range(1, 17))


def test_migrate_is_idempotent_and_preserves_data(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    result = migrate_sqlite(db_path)

    assert result.schema_versions == tuple(range(1, 17))
    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


class _SimulatedCrash(BaseException):
    """Substitutes for the process dying at an os-level mutation.

    BaseException so no ``except Exception`` cleanup can swallow it — a dead
    process runs no cleanup. Once it fires, every later intercepted mutation
    fails too, because a dead process performs no further syscalls.
    """


def _observe(db_path: Path) -> list[tuple[int, str]]:
    """What a fresh SQLite opener sees for this on-disk state.

    Opening mutates the state (WAL recovery, checkpoint-on-close), so callers
    probe each crash state exactly once.
    """
    conn = sqlite3.connect(db_path)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            return [(-1, f"integrity: {integrity}")]
        return conn.execute("SELECT id, v FROM t ORDER BY id").fetchall()
    except sqlite3.DatabaseError as exc:
        return [(-1, f"unreadable: {exc}")]
    finally:
        conn.close()


def _reference_rows(workdir: Path, main: bytes, wal: bytes | None) -> list[tuple[int, str]]:
    workdir.mkdir()
    db = workdir / "reference.sqlite"
    db.write_bytes(main)
    if wal is not None:
        Path(f"{db}-wal").write_bytes(wal)
    return _observe(db)


def _build_replay_fixture(
    base: Path,
) -> tuple[bytes, bytes, list[tuple[int, str]], bytes, list[tuple[int, str]]]:
    """Two geometry-matched databases, the old one with a hot (uncheckpointed) WAL.

    Same schema, same row count, same value sizes: SQLite lays both files out
    identically, so an old-database WAL frame replayed over the new main file
    lands inside the new database's live btree, where the corruption is
    *visible* to a reader. (With differing geometry the stale frames are still
    written into the file but can hide beyond the header's page count. Either
    way ``integrity_check`` reports 'ok' — this corruption is silent.)
    """
    old = base / "old-source.sqlite"
    conn = sqlite3.connect(old)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.executemany(
            "INSERT INTO t VALUES (?, ?)",
            [(i, f"old-{i:03d}-" + "x" * 100) for i in range(200)],
        )
        conn.commit()
        assert conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        # Committed, but resident ONLY in the WAL: the old database's main file
        # alone does not contain these values.
        conn.execute("UPDATE t SET v = 'old-updated' WHERE id < 3")
        conn.commit()
        old_main = old.read_bytes()
        old_wal = Path(f"{old}-wal").read_bytes()
    finally:
        conn.close()

    new = base / "new-source.sqlite"
    conn = sqlite3.connect(new)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
        conn.executemany(
            "INSERT INTO t VALUES (?, ?)",
            [(i, f"new-{i:03d}-" + "y" * 100) for i in range(200)],
        )
        conn.commit()
    finally:
        conn.close()  # the final close checkpoints: new-source is one file
    assert not Path(f"{new}-wal").exists()
    new_main = new.read_bytes()

    old_rows = _reference_rows(base / "reference-old", old_main, old_wal)
    # The planted pair really is a live hot-WAL database: the WAL-resident
    # update is visible through it.
    assert [v for _, v in old_rows[:3]] == ["old-updated"] * 3
    new_rows = _reference_rows(base / "reference-new", new_main, None)
    assert all(v.startswith("new-") for _, v in new_rows)
    assert old_rows != new_rows
    return old_main, old_wal, old_rows, new_main, new_rows


def test_replace_crash_leaves_old_or_new_database_never_a_hybrid(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash at ANY os-level mutation of the swap must leave a fresh opener
    seeing exactly the old database (including its WAL-resident commits) or
    exactly the new one.

    Today's ordering unlinks the destination's old sidecars only AFTER
    ``os.replace``. A crash in between leaves the new main file beside the old
    database's WAL — and SQLite binds a WAL to its database by NAME, not
    content, so the next opener replays old frames into the new file (with
    ``integrity_check`` 'ok' throughout). The mirror-image failure is equally
    forbidden: an aborted swap that has already discarded the old database's
    hot WAL loses rows the old database had committed. Both hybrids read as
    neither reference content below.
    """
    old_main, old_wal, old_rows, new_main, new_rows = _build_replay_fixture(tmp_path)

    state = {"calls": 0, "crash_at": 0}

    def _mutation(op):
        def run(*args: object, **kwargs: object) -> object:
            state["calls"] += 1
            if state["crash_at"] and state["calls"] >= state["crash_at"]:
                raise _SimulatedCrash(f"process died before mutation #{state['calls']}")
            return op(*args, **kwargs)

        return run

    # Path.unlink calls os.unlink, so these two cover every rename/removal the
    # swap performs. SQLite's own I/O is C-level and unaffected — a crash
    # inside a checkpoint is SQLite's own (already crash-safe) domain.
    monkeypatch.setattr(os, "replace", _mutation(os.replace))
    monkeypatch.setattr(os, "unlink", _mutation(os.unlink))

    def _plant(index: int) -> Path:
        case_dir = tmp_path / f"case-{index}"
        case_dir.mkdir()
        db = case_dir / "vinctor.sqlite"
        db.write_bytes(old_main)
        Path(f"{db}-wal").write_bytes(old_wal)
        return db

    def _build_new(tmp_db: Path) -> tuple[int, ...]:
        tmp_db.write_bytes(new_main)
        return (1,)

    # Count the os-level mutations of one whole successful swap.
    survivor = _plant(0)
    state["crash_at"] = 0
    state["calls"] = 0
    _atomic_replace_sqlite(survivor, _build_new)
    total_mutations = state["calls"]
    assert total_mutations >= 2
    assert _observe(survivor) == new_rows

    for crash_at in range(1, total_mutations + 1):
        db = _plant(crash_at)
        state["crash_at"] = crash_at
        state["calls"] = 0
        with pytest.raises(_SimulatedCrash):
            _atomic_replace_sqlite(db, _build_new)
        state["crash_at"] = 0  # the reboot: later opens run unimpeded
        seen = _observe(db)
        assert seen in (old_rows, new_rows), (
            f"crash before mutation #{crash_at}/{total_mutations} left a hybrid "
            f"database: fresh opener saw neither the old nor the new content "
            f"(first rows: {seen[:4]!r})"
        )


def test_replace_leaves_no_foreign_journal_beside_the_new_database(tmp_path: Path) -> None:
    """A ``-journal`` is the rollback-mode cousin of the stale-WAL hazard.

    Where the filesystem cannot support WAL, connect_sqlite falls back to
    rollback journaling (see the operational runbook), and a foreign hot
    journal beside a freshly swapped-in rollback-mode main file is *rolled
    back* into it by the next opener. (Beside a WAL-mode file SQLite deletes
    it unused — but the swap cannot know which world the next opener lives
    in.) So the swap must remove it along with the WAL sidecars.

    Driven through ``_atomic_replace_sqlite`` because the reset/restore
    entrypoints open the destination first to trace the pre-op audit head,
    and that open alone makes WAL-mode SQLite clean the journal — hiding
    whether the swap itself handles it.
    """
    db_path = tmp_path / "vinctor.sqlite"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE old_db (x INTEGER)")
        conn.commit()
    finally:
        conn.close()
    journal = Path(f"{db_path}-journal")
    journal.write_bytes(b"foreign rollback journal of the replaced database")

    def _build(tmp_db: Path) -> tuple[int, ...]:
        build_conn = sqlite3.connect(tmp_db)
        try:
            build_conn.execute("CREATE TABLE new_db (x INTEGER)")
            build_conn.commit()
        finally:
            build_conn.close()
        return (1,)

    _atomic_replace_sqlite(db_path, _build)

    assert not journal.exists()


def test_restore_replaces_corrupt_destination_and_its_stale_sidecars(tmp_path: Path) -> None:
    """Restore is the remedy for a corrupt database: a destination that cannot
    be read (and so cannot be checkpointed) must not block the swap, and its
    sidecars must not survive next to the restored file.
    """
    source = tmp_path / "source.sqlite"
    _seed_db(source)
    source_versions = read_schema_versions(source)
    target = tmp_path / "vinctor.sqlite"
    target.write_text("stale-not-a-db", encoding="utf-8")
    _plant_stale_sidecars(target)

    restore_sqlite(target, source)

    assert read_schema_versions(target) == source_versions
    assert all(not path.exists() for path in _sidecars(target))


def test_reset_fails_closed_while_a_destination_write_is_in_flight(tmp_path: Path) -> None:
    """A destination whose WAL cannot be checkpointed because a write is in
    flight aborts the swap with the old database fully intact — including the
    open transaction. Swapping under a live writer would corrupt far more
    than sidecars; the runbook's stop-the-service-first ordering is the
    contract. This raw sqlite3 connection does not participate in Vinctor's
    cooperative lifetime lease, so the SQLite checkpoint remains the
    defense-in-depth guard and turns the violation into an error.
    """
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)
    writer = sqlite3.connect(db_path)
    try:
        writer.execute("BEGIN IMMEDIATE")
        writer.execute("CREATE TABLE busy_probe (x INTEGER)")

        # The in-flight write keeps wal_checkpoint(TRUNCATE) busy; the reset
        # waits out the connection's busy timeout (~5s) and then fails closed.
        with pytest.raises(RuntimeError, match="busy"):
            reset_sqlite(db_path)
    finally:
        writer.rollback()
        writer.close()

    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(
            conn, initialize_schema=False
        ).grant_repository.get_by_ref("grt_seed")
    finally:
        conn.close()
    assert grant is not None


def test_replace_blocks_new_vinctor_writer_until_rename_finishes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No Vinctor opener may recreate the old database's WAL in the swap window.

    Pause exactly at ``os.replace``: destination checkpointing and sidecar
    removal have completed, but the new main file is not installed yet. A
    concurrent ``connect_sqlite`` writer must remain blocked until the rename
    finishes; otherwise it commits to the old main, recreates ``-wal``, and the
    rename can put that stale WAL beside the new database.
    """
    db_path = tmp_path / "vinctor.sqlite"
    seed = sqlite3.connect(db_path)
    try:
        seed.execute("PRAGMA journal_mode = WAL")
        seed.execute("CREATE TABLE stale_writer (value INTEGER)")
        seed.execute("INSERT INTO stale_writer VALUES (1)")
        seed.commit()
    finally:
        seed.close()
    assert not _sidecars(db_path)[0].exists()
    original_replace = os.replace
    replace_reached = threading.Event()
    allow_replace = threading.Event()
    writer_started = tmp_path / "writer-started"
    writer_committed = tmp_path / "writer-committed"
    release_writer = tmp_path / "release-writer"
    replace_errors: list[BaseException] = []
    writer_process: subprocess.Popen[str] | None = None

    def paused_replace(source: object, destination: object) -> None:
        replace_reached.set()
        assert allow_replace.wait(timeout=5)
        original_replace(source, destination)

    monkeypatch.setattr(os, "replace", paused_replace)

    def build_new(tmp_db: Path) -> tuple[int, ...]:
        conn = sqlite3.connect(tmp_db)
        try:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("CREATE TABLE stale_writer (value INTEGER)")
            conn.execute("INSERT INTO stale_writer VALUES (2)")
            conn.commit()
        finally:
            conn.close()
        return (1,)

    def replace() -> None:
        try:
            _atomic_replace_sqlite(db_path, build_new)
        except BaseException as exc:
            replace_errors.append(exc)

    def wait_for_file(path: Path, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return True
            time.sleep(0.01)
        return path.exists()

    writer_script = """
import sys
import time
from pathlib import Path
from vinctor_service.sqlite_txn import connect_sqlite

db_path, started_path, committed_path, release_path = map(Path, sys.argv[1:])
started_path.touch()
conn = connect_sqlite(db_path)
try:
    with conn:
        conn.execute("INSERT INTO stale_writer VALUES (99)")
    committed_path.touch()
    while not release_path.exists():
        time.sleep(0.01)
finally:
    conn.close()
"""

    replace_thread = threading.Thread(target=replace)
    replace_thread.start()
    try:
        assert replace_reached.wait(timeout=5)
        writer_process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                writer_script,
                str(db_path),
                str(writer_started),
                str(writer_committed),
                str(release_writer),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert wait_for_file(writer_started, timeout=5)

        # The replacement's cross-process exclusion must keep this writer out
        # of the checkpoint->rename window. Before the fix it commits here.
        writer_was_blocked = not wait_for_file(writer_committed, timeout=0.5)
        allow_replace.set()
        replace_thread.join(timeout=5)
        assert not replace_thread.is_alive()
        assert wait_for_file(writer_committed, timeout=5)
    finally:
        allow_replace.set()
        release_writer.touch()
        replace_thread.join(timeout=5)
        if writer_process is not None:
            try:
                _, writer_stderr = writer_process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                writer_process.kill()
                _, writer_stderr = writer_process.communicate()

    assert writer_was_blocked
    assert replace_errors == []
    assert writer_process is not None
    assert writer_process.returncode == 0, writer_stderr
    check = sqlite3.connect(db_path)
    try:
        assert check.execute("SELECT value FROM stale_writer ORDER BY value").fetchall() == [
            (2,),
            (99,),
        ]
    finally:
        check.close()


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


# ---------------------------------------------------------------------------
# PKA-40: schema-version startup gate — refuse a database newer than the binary
# ---------------------------------------------------------------------------


def _seed_future_schema_version(db_path: Path, version: int) -> None:
    """Stamp a schema version the binary does not know, as a newer binary would."""
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (version, NOW.isoformat()),
        )
        conn.commit()
    finally:
        conn.close()


def test_migrate_refuses_database_newer_than_binary(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)
    future = SQLITE_SCHEMA_VERSION_MAX + 1
    _seed_future_schema_version(db_path, future)

    with pytest.raises(SchemaVersionError) as excinfo:
        migrate_sqlite(db_path)

    message = str(excinfo.value)
    assert str(future) in message
    assert str(SQLITE_SCHEMA_VERSION_MAX) in message


def test_service_construction_refuses_database_newer_than_binary(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)
    _seed_future_schema_version(db_path, SQLITE_SCHEMA_VERSION_MAX + 1)

    conn = connect_sqlite(db_path)
    try:
        with pytest.raises(SchemaVersionError):
            SQLiteV1Service(conn)
    finally:
        conn.close()


def test_schema_gate_covers_services_that_skip_schema_apply(tmp_path: Path) -> None:
    # SQLiteServicePool constructs its non-primary services with
    # initialize_schema=False; the version gate must still fire for them.
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)
    _seed_future_schema_version(db_path, SQLITE_SCHEMA_VERSION_MAX + 1)

    conn = connect_sqlite(db_path)
    try:
        with pytest.raises(SchemaVersionError):
            SQLiteV1Service(conn, initialize_schema=False)
    finally:
        conn.close()


def test_migrate_accepts_equal_schema_version(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)

    result = migrate_sqlite(db_path)

    assert result.schema_versions == tuple(range(1, SQLITE_SCHEMA_VERSION_MAX + 1))


def test_migrate_upgrades_older_schema_version(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_db(db_path)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            "DELETE FROM schema_migrations WHERE version = ?",
            (SQLITE_SCHEMA_VERSION_MAX,),
        )
        conn.commit()
    finally:
        conn.close()

    result = migrate_sqlite(db_path)

    assert result.schema_versions == tuple(range(1, SQLITE_SCHEMA_VERSION_MAX + 1))


def test_known_max_schema_version_matches_applied_migrations(tmp_path: Path) -> None:
    # Drift guard: adding a migration without bumping SQLITE_SCHEMA_VERSION_MAX
    # must fail here — a constant that lags would refuse databases that are fine.
    conn = connect_sqlite(tmp_path / "fresh.sqlite")
    try:
        init_sqlite_schema(conn)
        versions = get_sqlite_schema_versions(conn)
    finally:
        conn.close()

    assert versions == tuple(range(1, SQLITE_SCHEMA_VERSION_MAX + 1))
    assert max(versions) == SQLITE_SCHEMA_VERSION_MAX


def test_backup_still_works_against_newer_database(tmp_path: Path) -> None:
    # `storage backup` opens raw and dumps SQL — version-agnostic, and exactly
    # what an operator wants BEFORE upgrading the binary. It must not be gated.
    db_path = tmp_path / "vinctor.sqlite"
    output_path = tmp_path / "vinctor.backup.sqlite"
    _seed_db(db_path)
    future = SQLITE_SCHEMA_VERSION_MAX + 1
    _seed_future_schema_version(db_path, future)

    result = backup_sqlite(db_path, output_path)

    assert result.bytes > 0
    assert future in result.schema_versions


def test_postgres_init_refuses_database_newer_than_binary(
    requires_postgres: str,
) -> None:
    from vinctor_service.postgres import (
        POSTGRES_SCHEMA_VERSION_MAX,
        connect_postgres,
        init_postgres_schema,
    )

    conn = connect_postgres(requires_postgres)
    try:
        init_postgres_schema(conn)
        future = POSTGRES_SCHEMA_VERSION_MAX + 1
        with conn.transaction():
            conn.execute(
                """
                INSERT INTO schema_migrations (version, applied_at)
                VALUES (%s, %s)
                ON CONFLICT (version) DO NOTHING
                """,
                (future, NOW),
            )
        try:
            with pytest.raises(SchemaVersionError) as excinfo:
                init_postgres_schema(conn)
            message = str(excinfo.value)
            assert str(future) in message
            assert str(POSTGRES_SCHEMA_VERSION_MAX) in message
        finally:
            # Clean up the future stamp so later tests (and reruns) against the
            # shared CI database are not refused by the gate under test.
            with conn.transaction():
                conn.execute(
                    "DELETE FROM schema_migrations WHERE version = %s", (future,)
                )
        # Equal version again: the gate clears once the future stamp is gone.
        init_postgres_schema(conn)
    finally:
        conn.close()


def test_postgres_schema_gate_covers_services_that_skip_schema_apply(
    requires_postgres: str,
) -> None:
    # Mirror of the SQLite invariant: a service constructed with
    # initialize_schema=False skips the schema APPLY, not the version gate — a
    # database newer than this binary must be refused on every construction
    # path (PKA-40).
    from vinctor_service.postgres import (
        POSTGRES_SCHEMA_VERSION_MAX,
        PostgresV1Service,
        connect_postgres,
        init_postgres_schema,
    )

    conn = connect_postgres(requires_postgres)
    try:
        init_postgres_schema(conn)
        future = POSTGRES_SCHEMA_VERSION_MAX + 1
        with conn.transaction():
            conn.execute(
                """
                INSERT INTO schema_migrations (version, applied_at)
                VALUES (%s, %s)
                ON CONFLICT (version) DO NOTHING
                """,
                (future, NOW),
            )
        try:
            with pytest.raises(SchemaVersionError) as excinfo:
                PostgresV1Service(conn, initialize_schema=False)
            message = str(excinfo.value)
            assert str(future) in message
            assert str(POSTGRES_SCHEMA_VERSION_MAX) in message
        finally:
            # Clean up the future stamp so later tests (and reruns) against the
            # shared CI database are not refused by the gate under test.
            with conn.transaction():
                conn.execute(
                    "DELETE FROM schema_migrations WHERE version = %s", (future,)
                )
        # Equal version again: the gate clears once the future stamp is gone.
        PostgresV1Service(conn, initialize_schema=False)
    finally:
        conn.close()


def test_postgres_known_max_schema_version_matches_applied_migrations(
    requires_postgres: str,
) -> None:
    from vinctor_service.postgres import (
        POSTGRES_SCHEMA_VERSION_MAX,
        connect_postgres,
        init_postgres_schema,
    )

    conn = connect_postgres(requires_postgres)
    try:
        init_postgres_schema(conn)
        with conn.transaction():
            row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    finally:
        conn.close()

    assert row is not None
    assert row[0] == POSTGRES_SCHEMA_VERSION_MAX


def test_postgres_cleanup_discovers_dynamic_tables_and_preserves_migrations(
    requires_postgres: str,
) -> None:
    from conftest import _clean_postgres_database

    from vinctor_service.postgres import connect_postgres, init_postgres_schema

    conn = connect_postgres(requires_postgres)
    try:
        init_postgres_schema(conn)
        with conn.transaction():
            conn.execute("DROP TABLE IF EXISTS pka71_dynamic_cleanup")
            conn.execute(
                "CREATE TABLE pka71_dynamic_cleanup (marker TEXT NOT NULL)"
            )
            conn.execute(
                "INSERT INTO pka71_dynamic_cleanup (marker) VALUES (%s)",
                ("leftover",),
            )
            migration_row = conn.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
    finally:
        conn.close()

    assert migration_row is not None
    _clean_postgres_database(requires_postgres)

    conn = connect_postgres(requires_postgres)
    try:
        with conn.transaction():
            dynamic_row = conn.execute(
                "SELECT COUNT(*) FROM pka71_dynamic_cleanup"
            ).fetchone()
            current_migration_row = conn.execute(
                "SELECT MAX(version) FROM schema_migrations"
            ).fetchone()
            conn.execute("DROP TABLE pka71_dynamic_cleanup")
    finally:
        conn.close()

    assert dynamic_row == (0,)
    assert current_migration_row == migration_row
