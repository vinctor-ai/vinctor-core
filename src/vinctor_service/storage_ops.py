from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path

from vinctor_service.sqlite import SQLiteV1Service, get_sqlite_schema_versions


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


def backup_sqlite(
    db_path: Path,
    output_path: Path,
    *,
    force: bool = False,
) -> BackupResult:
    """Write a consistent snapshot of the SQLite database to output_path.

    The database stores only key hashes and metadata, so the backup file
    carries no raw secrets.
    """
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


def reset_sqlite(db_path: Path) -> ResetResult:
    """Remove the SQLite database and recreate an empty initialized schema."""
    if db_path.exists():
        db_path.unlink()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    try:
        versions = SQLiteV1Service(conn).schema_versions()
    finally:
        conn.close()

    return ResetResult(db_path=db_path, schema_versions=versions)


def restore_sqlite(db_path: Path, input_path: Path) -> RestoreResult:
    """Replace the database at db_path with the snapshot at input_path.

    Validates that input_path is a usable Vinctor SQLite snapshot before
    touching db_path, so an invalid input never destroys the live database.
    """
    if not input_path.exists():
        raise FileNotFoundError(f"backup input not found: {input_path}")
    versions = read_schema_versions(input_path)
    if versions is None:
        raise ValueError(f"input is not a valid Vinctor SQLite snapshot: {input_path}")

    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    source = sqlite3.connect(input_path)
    try:
        dest = sqlite3.connect(db_path)
        try:
            source.backup(dest)
        finally:
            dest.close()
    finally:
        source.close()

    return RestoreResult(db_path=db_path, input_path=input_path, schema_versions=versions)


def migrate_sqlite(db_path: Path) -> MigrateResult:
    """Open the database, applying any pending schema setup, and report versions.

    The schema is applied on open, so this makes that step explicit and
    idempotent without destroying existing data.
    """
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
