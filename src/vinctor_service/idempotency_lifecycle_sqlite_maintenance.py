from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_lifecycle import (
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
    IdempotencyLifecycleRejected,
    IdempotencyLifecycleUnavailable,
)
from vinctor_service.idempotency_lifecycle_lock import SQLiteWriterAttestation
from vinctor_service.idempotency_models import IdempotencyResultUnavailable
from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore
from vinctor_service.idempotency_storage import (
    authenticate_completed_result,
    parse_completed_result_row,
)
from vinctor_service.sqlite import _atomic_write, init_sqlite_schema
from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite
from vinctor_service.storage_ops import backup_sqlite, migrate_sqlite

VerifiedSQLiteSnapshot = tuple[Path, bytes]
SQLiteLifecycleStore = tuple[SerializedSQLiteConnection, SQLiteIdempotencyStore]


@dataclass(frozen=True, slots=True)
class SQLiteRetirementUpdate:
    version: str
    active_version: str


def open_lifecycle_store(
    database: Path,
    keyring: IdempotencyKeyring,
) -> SQLiteLifecycleStore:
    try:
        database.parent.mkdir(parents=True, exist_ok=True)
        conn = connect_sqlite(database, check_same_thread=False)
        init_sqlite_schema(conn)
        return conn, SQLiteIdempotencyStore(conn, keyring=keyring)
    except (OSError, RuntimeError, sqlite3.Error):
        raise IdempotencyLifecycleUnavailable from None


def migrate_lifecycle_schema(
    database: Path,
    writer_attestations: Sequence[SQLiteWriterAttestation],
    *,
    confirm_traffic_closed: bool,
) -> None:
    if not confirm_traffic_closed:
        raise IdempotencyLifecycleRejected("traffic_closed_confirmation_required")
    with ExitStack() as guards:
        for writer_attestation in writer_attestations:
            guards.enter_context(writer_attestation.exclusive_guard())
        migrate_sqlite(database)


def create_verified_snapshot(
    database: Path,
    snapshot: Path,
) -> VerifiedSQLiteSnapshot:
    backup_sqlite(database, snapshot)
    return snapshot, _file_digest(snapshot)


def require_verified_snapshot(
    snapshot: Path,
    verified_snapshot: VerifiedSQLiteSnapshot | None,
) -> None:
    if verified_snapshot != (snapshot, _file_digest(snapshot)):
        raise IdempotencyLifecycleRejected("verified_snapshot_required")


def retire_lifecycle_version(
    conn: SerializedSQLiteConnection,
    update: SQLiteRetirementUpdate,
    keyring: IdempotencyKeyring,
) -> None:
    unexpired_results_remain = False
    try:
        with _atomic_write(conn):
            now_row = conn.execute(
                "SELECT CAST(strftime('%s', 'now') AS INTEGER)"
            ).fetchone()
            if now_row is None:
                raise IdempotencyLifecycleUnavailable
            now_epoch = int(now_row[0])
            result_rows = conn.execute(
                "SELECT workspace_id, principal, operation, key_hash, "
                "request_fingerprint, format_version, status_code, "
                "cipher_key_version, response_nonce, response_ciphertext, "
                "created_at_epoch, expires_at_epoch FROM idempotency_results "
                "WHERE cipher_key_version = ? ORDER BY rowid",
                (update.version,),
            ).fetchall()
            parsed_results = tuple(
                parse_completed_result_row(row) for row in result_rows
            )
            if any(record.expires_at_epoch > now_epoch for _, record in parsed_results):
                unexpired_results_remain = True
            if not unexpired_results_remain:
                for invocation, record in parsed_results:
                    authenticate_completed_result(invocation, record, keyring)
                    conn.execute(
                        "DELETE FROM idempotency_results "
                        "WHERE workspace_id = ? AND principal = ? "
                        "AND operation = ? AND key_hash = ?",
                        invocation.result_identity,
                    )
                cursor = conn.execute(
                    "UPDATE idempotency_cipher_key_versions "
                    "SET retired_epoch = COALESCE("
                    "retired_epoch, CAST(strftime('%s', 'now') AS INTEGER)"
                    ") "
                    "WHERE version_label = ? "
                    "AND write_disabled_epoch IS NOT NULL "
                    "AND drain_completed_epoch IS NOT NULL "
                    "AND drain_completed_epoch + ? "
                    "<= CAST(strftime('%s', 'now') AS INTEGER) "
                    "AND NOT EXISTS ("
                    "SELECT 1 FROM idempotency_results "
                    "WHERE cipher_key_version = ?"
                    ") AND EXISTS ("
                    "SELECT 1 FROM idempotency_cipher_key_versions "
                    "WHERE version_label = ? "
                    "AND write_disabled_epoch IS NULL AND retired_epoch IS NULL"
                    ")",
                    (
                        update.version,
                        IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                        update.version,
                        update.active_version,
                    ),
                )
                if cursor.rowcount != 1:
                    raise IdempotencyLifecycleUnavailable
    except (sqlite3.Error, IdempotencyResultUnavailable):
        raise IdempotencyLifecycleUnavailable from None
    if unexpired_results_remain:
        raise IdempotencyLifecycleRejected("unexpired_results_remain")


def _file_digest(path: Path) -> bytes:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            digest.update(chunk)
    return digest.digest()
