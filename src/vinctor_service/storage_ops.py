from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vinctor_service.audit_anchor import AuditAnchor, anchor_from_env, storage_op_line
from vinctor_service.audit_chain import GENESIS_PREV_HASH
from vinctor_service.sqlite import (
    SQLiteAuditWriter,
    SQLiteV1Service,
    get_sqlite_schema_versions,
)


@dataclass(frozen=True)
class BackupResult:
    db_path: Path
    output_path: Path
    bytes: int
    schema_versions: tuple[int, ...]


@dataclass(frozen=True)
class ResetResult:
    db_path: Path
    schema_versions: tuple[int, ...]


@dataclass(frozen=True)
class RestoreResult:
    db_path: Path
    input_path: Path
    schema_versions: tuple[int, ...]


@dataclass(frozen=True)
class MigrateResult:
    db_path: Path
    schema_versions: tuple[int, ...]


def read_audit_chain_head(db_path: Path) -> tuple[int, str]:
    """Read the audit chain head (seq, row_hash) directly from the DB file.

    Mirrors SQLiteAuditWriter.chain_head(): an absent database or an empty
    chain reports (0, GENESIS_PREV_HASH). Never creates or migrates the
    database. Raises on an unreadable database — callers treat that as
    head-unknown (fail-open).
    """
    if not db_path.exists():
        return (0, GENESIS_PREV_HASH)
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
    finally:
        conn.close()
    if row is None or row[0] is None or row[1] is None:
        return (0, GENESIS_PREV_HASH)
    return (row[0], row[1])


def _emit_storage_op_trace(op: str, db_path: Path, anchor: AuditAnchor | None) -> None:
    """Record that a storage op was attempted, BEFORE it touches the database.

    Emits one self-identifying JSON record (op name, ISO-8601 UTC timestamp,
    pre-op audit chain head) to stderr ALWAYS, and to the configured anchor
    (anchor_from_env when none is injected) — so a later reset/restore cannot
    silently erase the chain: the anchor still holds the head it had reached.
    Fail-open by contract: a failing head read or anchor sink is logged to
    stderr and never blocks the storage op.
    """
    at = datetime.now(UTC).isoformat()
    head_seq: int | None = None
    head_hash: str | None = None
    try:
        head_seq, head_hash = read_audit_chain_head(db_path)
    except Exception as exc:  # noqa: BLE001 - deliberate fail-open
        sys.stderr.write(f"vinctor: storage-op head read failed ({op}): {exc}\n")
    sys.stderr.write(
        "vinctor: storage-op trace " + storage_op_line(op, at, head_seq, head_hash) + "\n"
    )
    sink = anchor if anchor is not None else anchor_from_env(dict(os.environ))
    try:
        sink.emit_storage_op(op, at, head_seq, head_hash)
    except Exception as exc:  # noqa: BLE001 - deliberate fail-open
        sys.stderr.write(f"vinctor: storage-op anchor emit raised ({op}): {exc}\n")


def backup_sqlite(
    db_path: Path,
    output_path: Path,
    *,
    force: bool = False,
    anchor: AuditAnchor | None = None,
) -> BackupResult:
    """Write a consistent snapshot of the SQLite database to output_path.

    The database stores only key hashes and metadata, so the backup file
    carries no raw secrets.
    """
    _emit_storage_op_trace("backup", db_path, anchor)
    if not db_path.exists():
        raise FileNotFoundError(f"database not found: {db_path}")
    if output_path.exists():
        if not force:
            raise FileExistsError(
                f"backup output already exists: {output_path}; pass --force to overwrite"
            )
        output_path.unlink()
    output_path.parent.mkdir(parents=True, exist_ok=True)

    source = sqlite3.connect(db_path)
    try:
        dest = sqlite3.connect(output_path)
        try:
            source.backup(dest)
        finally:
            dest.close()
        versions = get_sqlite_schema_versions(source)
    finally:
        source.close()

    return BackupResult(
        db_path=db_path,
        output_path=output_path,
        bytes=output_path.stat().st_size,
        schema_versions=versions,
    )


def _atomic_replace_sqlite(
    db_path: Path, build: Callable[[Path], tuple[int, ...]]
) -> tuple[int, ...]:
    """Populate a fresh database in a sibling temp file and atomically swap it in.

    ``build`` writes the new database to the temp path and returns its schema
    versions; only after it succeeds and the file is flushed to disk does
    ``os.replace`` move it over ``db_path`` (an atomic rename on the same
    filesystem). A crash, a failing build, or a verification failure therefore
    leaves the existing database untouched rather than destroyed or half-written.
    """
    db_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=db_path.parent, prefix="." + db_path.name + ".", suffix=".tmp"
    )
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        versions = build(tmp_path)
        flush_fd = os.open(tmp_path, os.O_RDONLY)
        try:
            os.fsync(flush_fd)
        finally:
            os.close(flush_fd)
        os.replace(tmp_path, db_path)
        return versions
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        raise


def reset_sqlite(db_path: Path, *, anchor: AuditAnchor | None = None) -> ResetResult:
    """Recreate an empty initialized schema, swapping it in atomically.

    The empty database is built in a temp file and ``os.replace``d over the
    target, so an interrupted reset leaves the old database in place rather than
    no database at all.
    """
    _emit_storage_op_trace("reset", db_path, anchor)

    def _build(tmp_path: Path) -> tuple[int, ...]:
        conn = sqlite3.connect(tmp_path)
        try:
            return SQLiteV1Service(conn).schema_versions()
        finally:
            conn.close()

    versions = _atomic_replace_sqlite(db_path, _build)
    return ResetResult(db_path=db_path, schema_versions=versions)


def restore_sqlite(
    db_path: Path, input_path: Path, *, anchor: AuditAnchor | None = None
) -> RestoreResult:
    """Replace the database at db_path with the snapshot at input_path.

    Validates that input_path is a usable Vinctor SQLite snapshot before
    touching db_path, so an invalid input never destroys the live database.
    """
    _emit_storage_op_trace("restore", db_path, anchor)
    if not input_path.exists():
        raise FileNotFoundError(f"backup input not found: {input_path}")
    versions = read_schema_versions(input_path)
    if versions is None:
        raise ValueError(f"input is not a valid Vinctor SQLite snapshot: {input_path}")

    def _build(tmp_path: Path) -> tuple[int, ...]:
        source = sqlite3.connect(input_path)
        try:
            dest = sqlite3.connect(tmp_path)
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()
        # Verify the restored copy BEFORE it is allowed to replace the live
        # database: a readable schema and an intact audit hash-chain, so a
        # corrupt or tampered snapshot is rejected while the existing database
        # is still in place (the atomic swap only happens on success).
        verify_conn = sqlite3.connect(tmp_path)
        try:
            restored_versions = get_sqlite_schema_versions(verify_conn)
            chain = SQLiteAuditWriter(verify_conn).verify_chain()
        finally:
            verify_conn.close()
        if not restored_versions:
            raise ValueError("restored snapshot has no schema metadata")
        if not chain.ok:
            raise ValueError(
                f"restored snapshot has a broken audit chain at seq {chain.break_seq}"
            )
        return restored_versions

    swapped_versions = _atomic_replace_sqlite(db_path, _build)
    return RestoreResult(
        db_path=db_path, input_path=input_path, schema_versions=swapped_versions
    )


def migrate_sqlite(db_path: Path, *, anchor: AuditAnchor | None = None) -> MigrateResult:
    """Open the database, applying any pending schema setup, and report versions.

    The schema is applied on open, so this makes that step explicit and
    idempotent without destroying existing data.
    """
    _emit_storage_op_trace("migrate", db_path, anchor)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        versions = SQLiteV1Service(conn).schema_versions()
    finally:
        conn.close()
    return MigrateResult(db_path=db_path, schema_versions=versions)


def read_schema_versions(db_path: Path) -> tuple[int, ...] | None:
    """Return schema versions without creating or migrating the database.

    Returns None when no database file exists or it has no schema metadata,
    so read-only inspection never creates a database as a side effect.
    """
    if not db_path.exists():
        return None
    conn = sqlite3.connect(db_path)
    try:
        return get_sqlite_schema_versions(conn)
    except sqlite3.DatabaseError:
        return None
    finally:
        conn.close()
