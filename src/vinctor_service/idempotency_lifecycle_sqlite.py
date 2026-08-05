from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_lifecycle import (
    _PROBE_INVOCATION,
    IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
    IdempotencyLifecycleRejected,
    IdempotencyLifecycleStatus,
    IdempotencyLifecycleUnavailable,
    IdempotencyRetirementRequest,
)
from vinctor_service.idempotency_lifecycle_lock import SQLiteWriterAttestation
from vinctor_service.idempotency_lifecycle_sqlite_maintenance import (
    SQLiteRetirementUpdate,
    VerifiedSQLiteSnapshot,
    create_verified_snapshot,
    migrate_lifecycle_schema,
    open_lifecycle_store,
    require_verified_snapshot,
    retire_lifecycle_version,
)
from vinctor_service.sqlite import (
    _atomic_write,
    get_sqlite_schema_versions,
)
from vinctor_service.storage_ops import restore_sqlite


class SQLiteIdempotencyLifecycleBackend:
    __slots__ = (
        "_conn",
        "_database",
        "_keyring",
        "_store",
        "_verified_snapshot",
        "_writer_attestation",
    )

    def __init__(
        self,
        database: Path,
        *,
        keyring: IdempotencyKeyring,
    ) -> None:
        self._database = database
        self._keyring = keyring
        self._verified_snapshot: VerifiedSQLiteSnapshot | None = None
        self._writer_attestation = SQLiteWriterAttestation(
            database,
            keyring.active_version,
        )
        self._conn, self._store = open_lifecycle_store(
            self._database,
            self._keyring,
        )

    def statuses(self) -> tuple[IdempotencyLifecycleStatus, ...]:
        rows = self._conn.execute(
            "SELECT version_label FROM idempotency_cipher_key_versions ORDER BY version_label"
        ).fetchall()
        return tuple(self.status(str(row[0])) for row in rows)

    def status(self, version: str) -> IdempotencyLifecycleStatus:
        row = self._conn.execute(
            "SELECT key_commitment, reserved_encryption_slots, "
            "write_disabled_reason, write_disabled_epoch, drain_completed_epoch, "
            "retired_epoch FROM idempotency_cipher_key_versions "
            "WHERE version_label = ?",
            (version,),
        ).fetchone()
        if row is None:
            raise IdempotencyLifecycleRejected("unknown_version")
        required = tuple(
            str(required[0])
            for required in self._conn.execute(
                "SELECT DISTINCT cipher_key_version FROM idempotency_results "
                "WHERE cipher_key_version <> ? "
                "ORDER BY cipher_key_version",
                (self._keyring.active_version,),
            ).fetchall()
        )
        commitment = hashlib.sha256(
            b"vinctor.idempotency.commitment-id.v1\x00" + bytes(row[0])
        ).hexdigest()
        return IdempotencyLifecycleStatus(
            version=version,
            commitment_identifier=commitment,
            reserved_encryption_slots=int(row[1]),
            write_disabled_reason=None if row[2] is None else str(row[2]),
            write_disabled_epoch=None if row[3] is None else int(row[3]),
            drain_completed_epoch=None if row[4] is None else int(row[4]),
            retired_epoch=None if row[5] is None else int(row[5]),
            local_active_version=self._keyring.active_version,
            required_historical_versions=required,
        )

    def write_disable(self, version: str, reason: str) -> None:
        state = self.status(version)
        if state.retired_epoch is not None:
            raise IdempotencyLifecycleRejected("version_retired")
        if state.write_disabled_epoch is not None:
            if state.write_disabled_reason != reason:
                raise IdempotencyLifecycleRejected("write_disable_reason_conflict")
            return
        try:
            with _atomic_write(self._conn):
                self._conn.execute(
                    "UPDATE idempotency_cipher_key_versions "
                    "SET write_disabled_epoch = "
                    "CAST(strftime('%s', 'now') AS INTEGER), "
                    "write_disabled_reason = ? "
                    "WHERE version_label = ? AND write_disabled_epoch IS NULL "
                    "AND retired_epoch IS NULL",
                    (reason, version),
                )
        except sqlite3.Error:
            raise IdempotencyLifecycleUnavailable from None

    def complete_drain(self, version: str) -> None:
        with SQLiteWriterAttestation(
            self._database,
            version,
        ).exclusive_guard():
            state = self.status(version)
            if state.write_disabled_epoch is None:
                raise IdempotencyLifecycleRejected("write_disable_required")
            if state.retired_epoch is not None:
                raise IdempotencyLifecycleRejected("version_retired")
            if state.drain_completed_epoch is not None:
                return
            try:
                with _atomic_write(self._conn):
                    self._conn.execute(
                        "UPDATE idempotency_cipher_key_versions "
                        "SET drain_completed_epoch = COALESCE("
                        "drain_completed_epoch, "
                        "CAST(strftime('%s', 'now') AS INTEGER)"
                        ") "
                        "WHERE version_label = ? AND write_disabled_epoch IS NOT NULL "
                        "AND retired_epoch IS NULL",
                        (version,),
                    )
            except sqlite3.Error:
                raise IdempotencyLifecycleUnavailable from None

    def retire(self, request: IdempotencyRetirementRequest) -> None:
        with SQLiteWriterAttestation(
            self._database,
            request.version,
        ).exclusive_guard():
            state = self.status(request.version)
            if state.retired_epoch is not None:
                return
            if state.write_disabled_epoch is None or state.drain_completed_epoch is None:
                raise IdempotencyLifecycleRejected("drain_completion_required")
            now_epoch = self._database_epoch()
            if now_epoch < state.drain_completed_epoch + IDEMPOTENCY_REMOVAL_WINDOW_SECONDS:
                raise IdempotencyLifecycleRejected("removal_window_not_elapsed")
            active = self.status(self._keyring.active_version)
            if active.write_disabled_epoch is not None or active.retired_epoch is not None:
                raise IdempotencyLifecycleRejected("active_replacement_unavailable")
            retire_lifecycle_version(
                self._conn,
                SQLiteRetirementUpdate(
                    version=request.version,
                    active_version=self._keyring.active_version,
                ),
                self._keyring,
            )

    def reserve_nonce(self, version: str) -> None:
        if version != self._keyring.active_version:
            state = self.status(version)
            if state.write_disabled_epoch is not None or state.retired_epoch is not None:
                raise RuntimeError("idempotency write disabled")
            raise IdempotencyLifecycleRejected("version_not_active")
        self._store.reserve_nonce(_PROBE_INVOCATION, now_epoch=self._database_epoch())

    def register_active_writer(self, writer_id: str) -> None:
        if not writer_id:
            raise IdempotencyLifecycleRejected("writer_id_required")
        self._writer_attestation.register()

    def migrate_schema(self, *, confirm_traffic_closed: bool) -> None:
        migrate_lifecycle_schema(
            self._database,
            tuple(
                self._writer_attestation
                if version == self._keyring.active_version
                else SQLiteWriterAttestation(self._database, version)
                for version in sorted(self._keyring.version_labels)
            ),
            confirm_traffic_closed=confirm_traffic_closed,
        )

    def create_verified_snapshot(self, snapshot: Path) -> None:
        self._verified_snapshot = create_verified_snapshot(self._database, snapshot)

    def restore_verified_snapshot(self, snapshot: Path) -> None:
        require_verified_snapshot(snapshot, self._verified_snapshot)
        self._conn.close()
        try:
            restore_sqlite(self._database, snapshot)
        finally:
            self._conn, self._store = open_lifecycle_store(
                self._database,
                self._keyring,
            )

    def schema_versions(self) -> tuple[int, ...]:
        return get_sqlite_schema_versions(self._conn)

    def close(self) -> None:
        self._writer_attestation.close()
        self._conn.close()

    def _database_epoch(self) -> int:
        return self._store.database_epoch()
