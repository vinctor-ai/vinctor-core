from __future__ import annotations

import secrets
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from vinctor_service.idempotency_crypto import (
    encrypt_reserved_response as encrypt_response,
)
from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    CryptoReservation,
    IdempotencyInvocation,
    IdempotencyKeyVersionState,
    IdempotencyLookupResult,
    IdempotencyMutation,
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
    PreSerializedHttpResponse,
)
from vinctor_service.idempotency_sqlite_completion import (
    SQLiteCompletionAttempt,
    claim_and_complete_sqlite_result,
    gc_sqlite_results,
)
from vinctor_service.idempotency_sqlite_executor import (
    SQLiteIdempotentMutationExecutor as SQLiteIdempotentMutationExecutor,
)
from vinctor_service.idempotency_storage import (
    HARD_SLOT_LIMIT,
    NONCE_BYTES,
    SOFT_SLOT_LIMIT,
    CompletedResultRecord,
    classify_completed_result,
    parse_key_version_state,
)
from vinctor_service.sqlite_txn import (
    SerializedSQLiteConnection,
    conn_txn_lock,
    require_serialized,
)


class _HardLimitReached(Exception): ...


class _NonceCollision(Exception): ...


class SQLiteIdempotencyStore:
    def __init__(
        self,
        conn: SerializedSQLiteConnection,
        *,
        keyring: IdempotencyKeyring | None,
        nonce_factory: Callable[[int], bytes] | None = None,
    ) -> None:
        self.conn = require_serialized(conn)
        self.keyring = keyring
        self.nonce_factory = nonce_factory or secrets.token_bytes
        self._register_keyring()

    def database_epoch(self) -> int:
        try:
            row = self.conn.execute("SELECT CAST(strftime('%s', 'now') AS INTEGER)").fetchone()
        except sqlite3.Error:
            raise IdempotencyResultUnavailable from None
        if row is None:
            raise IdempotencyResultUnavailable
        return int(row[0])

    def lookup(
        self,
        invocation: IdempotencyInvocation,
        *,
        now_epoch: int,
    ) -> IdempotencyLookupResult:
        try:
            row = self.conn.execute(
                "SELECT request_fingerprint, format_version, status_code, "
                "cipher_key_version, response_nonce, response_ciphertext, "
                "created_at_epoch, expires_at_epoch FROM idempotency_results "
                "WHERE workspace_id = ? AND principal = ? "
                "AND operation = ? AND key_hash = ?",
                invocation.result_identity,
            ).fetchone()
        except sqlite3.Error:
            raise IdempotencyResultUnavailable from None
        if row is None:
            return classify_completed_result(invocation, None, self.keyring, now_epoch=now_epoch)
        try:
            record = CompletedResultRecord(
                request_fingerprint=bytes(row[0]),
                format_version=int(row[1]),
                status_code=int(row[2]),
                cipher_key_version=str(row[3]),
                response_nonce=bytes(row[4]),
                response_ciphertext=bytes(row[5]),
                created_at_epoch=int(row[6]),
                expires_at_epoch=int(row[7]),
            )
        except (OverflowError, TypeError, ValueError):
            raise IdempotencyResultUnavailable from None
        return classify_completed_result(invocation, record, self.keyring, now_epoch=now_epoch)

    def reserve_nonce(
        self,
        invocation: IdempotencyInvocation,
        *,
        now_epoch: int,
    ) -> CryptoReservation:
        if self.keyring is None:
            raise IdempotencyWriteUnavailable
        version = self.keyring.active_version
        try:
            with self._transaction():
                row = self.conn.execute(
                    """
                    UPDATE idempotency_cipher_key_versions
                    SET reserved_encryption_slots = reserved_encryption_slots + 1
                    WHERE version_label = ?
                      AND write_disabled_epoch IS NULL
                      AND retired_epoch IS NULL
                      AND reserved_encryption_slots < ?
                    RETURNING reserved_encryption_slots
                    """,
                    (version, HARD_SLOT_LIMIT),
                ).fetchone()
                if row is None:
                    state = self._key_version_state(version)
                    if (
                        state.reserved_encryption_slots >= HARD_SLOT_LIMIT
                        and state.write_disabled_epoch is None
                        and state.retired_epoch is None
                    ):
                        raise _HardLimitReached
                    raise IdempotencyWriteUnavailable
                slots = int(row[0])
                if slots >= SOFT_SLOT_LIMIT:
                    self.conn.execute(
                        """
                        UPDATE idempotency_cipher_key_versions
                        SET soft_limit_reported_epoch = ?
                        WHERE version_label = ? AND soft_limit_reported_epoch IS NULL
                        """,
                        (now_epoch, version),
                    )
                try:
                    nonce = self.nonce_factory(NONCE_BYTES)
                except OSError:
                    raise IdempotencyWriteUnavailable from None
                if len(nonce) != NONCE_BYTES:
                    raise IdempotencyWriteUnavailable
                owner = invocation.reservation_owner_identity
                inserted = self.conn.execute(
                    """
                    INSERT OR IGNORE INTO idempotency_cipher_nonces
                        (cipher_key_version, slot, nonce, reserved_at_epoch,
                         workspace_id, principal, operation, key_hash,
                         request_fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (version, slots, nonce, now_epoch, *owner),
                )
                if inserted.rowcount != 1:
                    raise _NonceCollision
        except _HardLimitReached:
            self._write_disable(version, "hard_limit", now_epoch)
            raise IdempotencyWriteUnavailable from None
        except _NonceCollision:
            self._write_disable(version, "nonce_collision", now_epoch)
            raise IdempotencyWriteUnavailable from None
        except sqlite3.Error:
            raise IdempotencyWriteUnavailable from None
        return CryptoReservation(version, slots, nonce, now_epoch)

    def complete(
        self,
        invocation: IdempotencyInvocation,
        reservation: CryptoReservation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse:
        return claim_and_complete_sqlite_result(
            self,
            SQLiteCompletionAttempt(invocation, reservation, mutation),
            encrypt_response,
        )

    def gc_expired_results(self, *, limit: int = 100) -> int:
        return gc_sqlite_results(self, limit=limit)

    def key_version_state(self, version: str) -> IdempotencyKeyVersionState:
        try:
            return self._key_version_state(version)
        except sqlite3.Error:
            raise IdempotencyResultUnavailable from None

    def write_disable(self, *, version: str, reason: str) -> None:
        now_epoch = self.database_epoch()
        try:
            self._write_disable(version, reason, now_epoch)
        except sqlite3.Error:
            raise IdempotencyWriteUnavailable from None

    def _register_keyring(self) -> None:
        if self.keyring is None:
            return
        try:
            with self._transaction():
                for registration in self.keyring.registrations:
                    self.conn.execute(
                        """
                        INSERT OR IGNORE INTO idempotency_cipher_key_versions
                            (version_label, key_commitment,
                             reserved_encryption_slots, first_seen_epoch)
                        VALUES (?, ?, 0, CAST(strftime('%s', 'now') AS INTEGER))
                        """,
                        (registration.version, registration.commitment),
                    )
                    row = self.conn.execute(
                        "SELECT key_commitment FROM idempotency_cipher_key_versions "
                        "WHERE version_label = ?",
                        (registration.version,),
                    ).fetchone()
                    if row is None or bytes(row[0]) != registration.commitment:
                        raise IdempotencyWriteUnavailable
        except sqlite3.Error:
            raise IdempotencyWriteUnavailable from None

    def _key_version_state(self, version: str) -> IdempotencyKeyVersionState:
        row = self.conn.execute(
            "SELECT reserved_encryption_slots, first_seen_epoch, "
            "soft_limit_reported_epoch, write_disabled_epoch, "
            "write_disabled_reason, drain_completed_epoch, retired_epoch "
            "FROM idempotency_cipher_key_versions WHERE version_label = ?",
            (version,),
        ).fetchone()
        if row is None:
            raise IdempotencyWriteUnavailable
        return parse_key_version_state(version, tuple(row))

    def _write_disable(self, version: str, reason: str, now_epoch: int) -> None:
        with self._transaction():
            self.conn.execute(
                "UPDATE idempotency_cipher_key_versions "
                "SET write_disabled_epoch = COALESCE(write_disabled_epoch, ?), "
                "write_disabled_reason = COALESCE(write_disabled_reason, ?) "
                "WHERE version_label = ? AND retired_epoch IS NULL",
                (now_epoch, reason, version),
            )

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        with conn_txn_lock(self.conn):
            if self.conn.in_transaction:
                raise IdempotencyWriteUnavailable
            self.conn.execute("BEGIN IMMEDIATE")
            body_completed = False
            try:
                with self.conn:
                    yield
                    body_completed = True
            except sqlite3.Error:
                if body_completed:
                    raise AmbiguousCommitError from None
                raise
