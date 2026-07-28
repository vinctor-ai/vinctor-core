from __future__ import annotations

import hashlib
from contextlib import ExitStack
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
from vinctor_service.idempotency_lifecycle_postgres_lock import (
    PostgresWriterAttestation,
)
from vinctor_service.idempotency_lifecycle_postgres_recovery import (
    PostgresLifecycleRecovery,
    _RecoveryAuthorityAdapter,
)
from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
)
from vinctor_service.idempotency_postgres import PostgresIdempotencyStore
from vinctor_service.postgres import init_postgres_schema
from vinctor_service.postgres_connection import connect_postgres
from vinctor_service.postgres_driver import PostgresError


class PostgresIdempotencyLifecycleBackend:
    __slots__ = ("_conn", "_keyring", "_recovery", "_store", "_writer_attestation")

    def __init__(self, dsn: str, *, keyring: IdempotencyKeyring) -> None:
        self._keyring = keyring
        try:
            self._conn = connect_postgres(dsn)
            init_postgres_schema(self._conn)
            self._store = PostgresIdempotencyStore(self._conn, keyring=keyring)
            self._recovery = PostgresLifecycleRecovery(self._conn, keyring)
            self._writer_attestation = PostgresWriterAttestation(
                self._conn,
                keyring.active_version,
            )
        except (PostgresError, RuntimeError) as exc:
            # Chained, not `from None`: a refusal to start carries an actionable
            # message (an unsupported psycopg/libpq, for instance) and the
            # operator on this CLI path was being told only "unavailable".
            raise IdempotencyLifecycleUnavailable from exc

    def statuses(self) -> tuple[IdempotencyLifecycleStatus, ...]:
        try:
            with self._conn.transaction():
                rows = self._conn.execute(
                    "SELECT version_label FROM idempotency_cipher_key_versions "
                    "ORDER BY version_label"
                ).fetchall()
            return tuple(self.status(str(row[0])) for row in rows)
        except PostgresError:
            raise IdempotencyLifecycleUnavailable from None

    def status(self, version: str) -> IdempotencyLifecycleStatus:
        try:
            with self._conn.transaction():
                row = self._conn.execute(
                    "SELECT key_commitment, reserved_encryption_slots, "
                    "write_disabled_reason, write_disabled_epoch, drain_completed_epoch, "
                    "retired_epoch FROM idempotency_cipher_key_versions "
                    "WHERE version_label = %s",
                    (version,),
                ).fetchone()
                required_rows = self._conn.execute(
                    "SELECT DISTINCT cipher_key_version FROM idempotency_results "
                    "WHERE cipher_key_version <> %s "
                    "ORDER BY cipher_key_version",
                    (self._keyring.active_version,),
                ).fetchall()
        except PostgresError:
            raise IdempotencyLifecycleUnavailable from None
        if row is None:
            raise IdempotencyLifecycleRejected("unknown_version")
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
            required_historical_versions=tuple(str(required[0]) for required in required_rows),
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
            self._store.write_disable(version=version, reason=reason)
        except RuntimeError:
            raise IdempotencyLifecycleUnavailable from None

    def complete_drain(self, version: str) -> None:
        with PostgresWriterAttestation(
            self._conn,
            version,
        ).exclusive_guard():
            state = self.status(version)
            if state.write_disabled_epoch is None:
                raise IdempotencyLifecycleRejected("write_disable_required")
            if state.retired_epoch is not None:
                raise IdempotencyLifecycleRejected("version_retired")
            if state.drain_completed_epoch is not None:
                return
            generation = self._conn.generation
            try:
                with self._conn.transaction():
                    updated = self._conn.execute(
                        "UPDATE idempotency_cipher_key_versions "
                        "SET drain_completed_epoch = COALESCE("
                        "drain_completed_epoch, "
                        "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
                        ") "
                        "WHERE version_label = %s AND write_disabled_epoch IS NOT NULL "
                        "AND retired_epoch IS NULL "
                        "RETURNING drain_completed_epoch",
                        (version,),
                    ).fetchone()
                    if updated is None:
                        raise IdempotencyLifecycleUnavailable
            except AmbiguousCommitError:
                self._recovery.drain(
                    version,
                    generation=generation,
                )
            except PostgresError:
                raise IdempotencyLifecycleUnavailable from None

    def retire(self, request: IdempotencyRetirementRequest) -> None:
        with PostgresWriterAttestation(
            self._conn,
            request.version,
        ).exclusive_guard():
            state = self.status(request.version)
            if state.retired_epoch is not None:
                return
            if state.write_disabled_epoch is None or state.drain_completed_epoch is None:
                raise IdempotencyLifecycleRejected("drain_completion_required")
            generation = self._conn.generation
            unexpired_results_remain = False
            try:
                with self._conn.transaction():
                    now_epoch = self._database_epoch()
                    if now_epoch < state.drain_completed_epoch + IDEMPOTENCY_REMOVAL_WINDOW_SECONDS:
                        raise IdempotencyLifecycleRejected("removal_window_not_elapsed")
                    active = self._conn.execute(
                        "SELECT write_disabled_epoch, retired_epoch "
                        "FROM idempotency_cipher_key_versions "
                        "WHERE version_label = %s",
                        (self._keyring.active_version,),
                    ).fetchone()
                    if active is None or active[0] is not None or active[1] is not None:
                        raise IdempotencyLifecycleRejected("active_replacement_unavailable")
                    outcome = _RecoveryAuthorityAdapter(
                        self._conn
                    ).retire_if_eligible(
                        request.version,
                        active_version=self._keyring.active_version,
                        keyring=self._keyring,
                    )
                    if outcome.unexpired_results_remain:
                        unexpired_results_remain = True
                    elif outcome.retired_epoch is None:
                        raise IdempotencyLifecycleUnavailable
            except AmbiguousCommitError:
                self._recovery.retire(request.version, generation=generation)
            except PostgresError:
                raise IdempotencyLifecycleUnavailable from None
            if unexpired_results_remain:
                raise IdempotencyLifecycleRejected("unexpired_results_remain")

    def reserve_nonce(self, version: str) -> None:
        if version != self._keyring.active_version:
            state = self.status(version)
            if state.write_disabled_epoch is not None or state.retired_epoch is not None:
                raise RuntimeError("idempotency write disabled")
            raise IdempotencyLifecycleRejected("version_not_active")
        self._store.reserve_nonce(_PROBE_INVOCATION, now_epoch=self._store.database_epoch())

    def register_active_writer(self, writer_id: str) -> None:
        if not writer_id:
            raise IdempotencyLifecycleRejected("writer_id_required")
        self._writer_attestation.register()

    def migrate_schema(self, *, confirm_traffic_closed: bool) -> None:
        if not confirm_traffic_closed:
            raise IdempotencyLifecycleRejected("traffic_closed_confirmation_required")
        with ExitStack() as guards:
            for version in sorted(self._keyring.version_labels):
                attestation = (
                    self._writer_attestation
                    if version == self._keyring.active_version
                    else PostgresWriterAttestation(self._conn, version)
                )
                guards.enter_context(attestation.exclusive_guard())
            init_postgres_schema(self._conn)

    def create_verified_snapshot(self, snapshot: Path) -> None:
        raise IdempotencyLifecycleRejected("external_postgres_snapshot_required")

    def restore_verified_snapshot(self, snapshot: Path) -> None:
        raise IdempotencyLifecycleRejected("external_postgres_snapshot_required")

    def schema_versions(self) -> tuple[int, ...]:
        try:
            with self._conn.transaction():
                rows = self._conn.execute(
                    "SELECT version FROM schema_migrations ORDER BY version"
                ).fetchall()
            return tuple(int(row[0]) for row in rows)
        except PostgresError:
            raise IdempotencyLifecycleUnavailable from None

    def close(self) -> None:
        try:
            self._writer_attestation.close()
        finally:
            self._conn.close()

    def _database_epoch(self) -> int:
        row = self._conn.execute(
            "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
        ).fetchone()
        if row is None:
            raise IdempotencyLifecycleUnavailable
        return int(row[0])
