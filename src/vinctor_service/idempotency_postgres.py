from __future__ import annotations

import secrets
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from functools import partial

from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_models import (
    CryptoReservation,
    IdempotencyConflict,
    IdempotencyInvocation,
    IdempotencyKeyVersionState,
    IdempotencyLookupResult,
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_postgres_barrier import (
    complete_postgres_write_disable,
)
from vinctor_service.idempotency_postgres_completion import PostgresCompletionMixin
from vinctor_service.idempotency_postgres_executor import (
    PostgresIdempotentMutationExecutor,
)
from vinctor_service.idempotency_postgres_recovery import (
    lookup_on_current_postgres_connection,
    signed_advisory_key,
)
from vinctor_service.idempotency_postgres_state import (
    load_postgres_key_version_state,
    register_postgres_keyring,
)
from vinctor_service.idempotency_readiness import (
    postgres_idempotency_ready,
    require_postgres_idempotency_compatible,
    require_postgres_idempotency_ready,
)
from vinctor_service.idempotency_storage import (
    HARD_SLOT_LIMIT,
    NONCE_BYTES,
    SOFT_SLOT_LIMIT,
)
from vinctor_service.postgres_connection import SerializedPostgresConnection
from vinctor_service.postgres_driver import PostgresError

__all__ = ("PostgresIdempotentMutationExecutor", "signed_advisory_key")


class _HardLimitReached(Exception): ...


class _NonceCollision(Exception): ...


class PostgresIdempotencyStore(PostgresCompletionMixin):
    def __init__(
        self,
        conn: SerializedPostgresConnection,
        *,
        keyring: IdempotencyKeyring | None,
        nonce_factory: Callable[[int], bytes] | None = None,
    ) -> None:
        self.conn = conn
        self.keyring = keyring
        self.nonce_factory = nonce_factory or secrets.token_bytes
        self._register_keyring()
        compatible = partial(require_postgres_idempotency_compatible, keyring=keyring)
        ready = partial(require_postgres_idempotency_ready, keyring=keyring)
        self.conn.add_replacement_validator(compatible)
        self.conn.add_readiness_validator(ready)

    def database_epoch(self) -> int:
        try:
            with self._transaction(error=IdempotencyResultUnavailable):
                row = self.conn.execute(
                    "SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT"
                ).fetchone()
        except PostgresError:
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
            with self._transaction(error=IdempotencyResultUnavailable):
                return lookup_on_current_postgres_connection(
                    self.conn,
                    invocation,
                    self.keyring,
                    now_epoch=now_epoch,
                )
        except PostgresError:
            raise IdempotencyResultUnavailable from None

    def fresh_authoritative_lookup(
        self,
        invocation: IdempotencyInvocation,
        *,
        now_epoch: int,
        after_generation: int,
    ) -> IdempotencyLookupResult:
        try:
            with self.conn.fresh_authoritative_read(after_generation=after_generation):
                return lookup_on_current_postgres_connection(
                    self.conn,
                    invocation,
                    self.keyring,
                    now_epoch=now_epoch,
                )
        except IdempotencyConflict:
            raise
        except (PostgresError, RuntimeError):
            raise IdempotencyResultUnavailable from None

    def readiness(self) -> bool:
        if not self.conn.is_ready:
            return False
        try:
            with self._transaction(error=IdempotencyResultUnavailable):
                return postgres_idempotency_ready(self.conn, self.keyring)
        except Exception:
            return False

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
                    WHERE version_label = %s
                      AND write_disabled_epoch IS NULL
                      AND retired_epoch IS NULL
                      AND reserved_encryption_slots < %s
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
                        SET soft_limit_reported_epoch = %s
                        WHERE version_label = %s AND soft_limit_reported_epoch IS NULL
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
                    INSERT INTO idempotency_cipher_nonces
                        (cipher_key_version, slot, nonce, reserved_at_epoch,
                         workspace_id, principal, operation, key_hash,
                         request_fingerprint)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT DO NOTHING
                    RETURNING nonce
                    """,
                    (version, slots, nonce, now_epoch, *owner),
                ).fetchone()
                if inserted is None:
                    raise _NonceCollision
        except _HardLimitReached:
            self._complete_write_disable(version, "hard_limit", now_epoch)
            raise IdempotencyWriteUnavailable from None
        except _NonceCollision:
            self._complete_write_disable(version, "nonce_collision", now_epoch)
            raise IdempotencyWriteUnavailable from None
        except PostgresError:
            raise IdempotencyWriteUnavailable from None
        return CryptoReservation(version, slots, nonce, now_epoch)

    def key_version_state(self, version: str) -> IdempotencyKeyVersionState:
        try:
            with self._transaction(error=IdempotencyResultUnavailable):
                return self._key_version_state(version)
        except PostgresError:
            raise IdempotencyResultUnavailable from None

    def write_disable(self, *, version: str, reason: str) -> None:
        now_epoch = self.database_epoch()
        self._complete_write_disable(version, reason, now_epoch)

    def _complete_write_disable(
        self,
        version: str,
        reason: str,
        now_epoch: int,
    ) -> None:
        complete_postgres_write_disable(
            self.conn,
            version=version,
            reason=reason,
            now_epoch=now_epoch,
            transaction=self._transaction,
        )

    def _register_keyring(self) -> None:
        if self.keyring is None:
            return
        register_postgres_keyring(self.conn, self.keyring, self._transaction)

    def _key_version_state(self, version: str) -> IdempotencyKeyVersionState:
        return load_postgres_key_version_state(self.conn, version)

    @contextmanager
    def _transaction(
        self,
        error: type[RuntimeError] = IdempotencyWriteUnavailable,
    ) -> Iterator[None]:
        with self.conn.lock:
            if int(self.conn.info.transaction_status) != 0:
                raise error
            with self.conn.transaction():
                yield
