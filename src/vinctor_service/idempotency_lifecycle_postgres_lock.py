from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, contextmanager
from types import TracebackType
from typing import Final, Protocol, TypeAlias, runtime_checkable

from vinctor_service.idempotency_lifecycle import (
    IdempotencyLifecycleActiveWriters,
    IdempotencyLifecycleUnavailable,
)
from vinctor_service.idempotency_lifecycle_lock import (
    _version_lock_carrier,
    _version_lock_identity,
)
from vinctor_service.postgres_driver import PostgresError

DatabaseValue: TypeAlias = str | int | bool | bytes | None
_REGISTRY_LOCK: Final = int.from_bytes(
    hashlib.sha256(b"vinctor.idempotency.writer-lock.registry.v1").digest()[:8],
    "big",
) & ((2**63) - 1)


class _QueryResult(Protocol):
    def fetchone(self) -> Sequence[DatabaseValue] | None: ...

    def fetchall(self) -> Sequence[Sequence[DatabaseValue]]: ...


class _AttestationConnection(Protocol):
    def transaction(self) -> AbstractContextManager[None]: ...

    def execute(
        self,
        query: str,
        params: Sequence[DatabaseValue] = (),
    ) -> _QueryResult: ...

    def close(self) -> None: ...


@runtime_checkable
class _ReplacementManagedConnection(Protocol):
    def add_replacement_validator(
        self,
        validator: Callable[[_AttestationConnection], None],
    ) -> None: ...


@runtime_checkable
class _QuarantineAwareConnection(Protocol):
    @property
    def is_quarantined(self) -> bool: ...


class PostgresWriterAttestation:
    __slots__ = (
        "_carrier",
        "_conn",
        "_identity",
        "_registered",
        "_validator_added",
        "_version",
    )

    def __init__(self, conn: _AttestationConnection, version: str) -> None:
        self._carrier = _postgres_lock_carrier(version)
        self._conn = conn
        self._identity = _version_lock_identity(version)
        self._registered = False
        self._validator_added = False
        self._version = version

    @contextmanager
    def registration_guard(self) -> Iterator[None]:
        if self._registered:
            yield
            return
        registry_acquired = False
        shared_acquired = False
        completed = False
        postgres_failure = False
        try:
            self._acquire_registry(self._conn)
            registry_acquired = True
            self._assert_unique_carrier(self._conn)
            self._acquire_shared(self._conn)
            shared_acquired = True
            yield
            completed = True
        except PostgresError:
            postgres_failure = True
        finally:
            if registry_acquired and not postgres_failure:
                self._release_registry(self._conn)
            if shared_acquired and not completed and not postgres_failure:
                self._release_shared(self._conn)
        if postgres_failure:
            _fail_closed(self._conn)
        self._registered = True
        if not self._validator_added and isinstance(self._conn, _ReplacementManagedConnection):
            self._conn.add_replacement_validator(self._register_replacement)
            self._validator_added = True

    def register(self) -> None:
        with self.registration_guard():
            pass

    def _register_replacement(self, connection: _AttestationConnection) -> None:
        if not self._registered:
            return
        registry_acquired = False
        postgres_failure = False
        try:
            connection.execute(
                "SELECT pg_advisory_lock(%s)",
                (_REGISTRY_LOCK,),
            )
            registry_acquired = True
            self._assert_unique_carrier(connection)
            connection.execute(
                "SELECT pg_advisory_lock_shared(%s)",
                (self._carrier,),
            )
        except PostgresError:
            postgres_failure = True
        finally:
            if registry_acquired and not postgres_failure:
                self._release_registry_in_transaction(connection)
        if postgres_failure:
            _fail_closed(connection)

    def exclusive_guard(self) -> _PostgresExclusiveGuard:
        return _PostgresExclusiveGuard(self)

    def _acquire_exclusive(self) -> None:
        if self._registered:
            raise IdempotencyLifecycleActiveWriters
        registry_acquired = False
        exclusive_acquired = False
        postgres_failure = False
        try:
            self._acquire_registry(self._conn)
            registry_acquired = True
            self._assert_unique_carrier(self._conn)
            exclusive_acquired = self._try_exclusive(self._conn)
        except PostgresError:
            postgres_failure = True
        finally:
            if registry_acquired and not postgres_failure:
                self._release_registry(self._conn)
        if postgres_failure:
            _fail_closed(self._conn)
        if not exclusive_acquired:
            raise IdempotencyLifecycleActiveWriters

    def close(self) -> None:
        if not self._registered:
            return
        self._registered = False
        if isinstance(self._conn, _QuarantineAwareConnection) and self._conn.is_quarantined:
            return
        self._release_shared(self._conn)

    def _assert_unique_carrier(self, connection: _AttestationConnection) -> None:
        with connection.transaction():
            rows = connection.execute(
                "SELECT version_label FROM idempotency_cipher_key_versions ORDER BY version_label"
            ).fetchall()
        for row in rows:
            existing_version = str(row[0])
            if (
                _version_lock_identity(existing_version) != self._identity
                and _postgres_lock_carrier(existing_version) == self._carrier
            ):
                raise IdempotencyLifecycleUnavailable

    @staticmethod
    def _acquire_registry(connection: _AttestationConnection) -> None:
        with connection.transaction():
            connection.execute(
                "SELECT pg_advisory_lock(%s)",
                (_REGISTRY_LOCK,),
            )

    @staticmethod
    def _release_registry(connection: _AttestationConnection) -> None:
        try:
            with connection.transaction():
                PostgresWriterAttestation._release_registry_in_transaction(connection)
        except PostgresError:
            _fail_closed(connection)

    @staticmethod
    def _release_registry_in_transaction(
        connection: _AttestationConnection,
    ) -> None:
        row = connection.execute(
            "SELECT pg_advisory_unlock(%s)",
            (_REGISTRY_LOCK,),
        ).fetchone()
        if row is None or not bool(row[0]):
            _fail_closed(connection)

    def _acquire_shared(self, connection: _AttestationConnection) -> None:
        with connection.transaction():
            connection.execute(
                "SELECT pg_advisory_lock_shared(%s)",
                (self._carrier,),
            )

    def _release_shared(self, connection: _AttestationConnection) -> None:
        try:
            with connection.transaction():
                row = connection.execute(
                    "SELECT pg_advisory_unlock_shared(%s)",
                    (self._carrier,),
                ).fetchone()
                if row is None or not bool(row[0]):
                    _fail_closed(connection)
        except PostgresError:
            _fail_closed(connection)

    def _try_exclusive(self, connection: _AttestationConnection) -> bool:
        with connection.transaction():
            row = connection.execute(
                "SELECT pg_try_advisory_lock(%s)",
                (self._carrier,),
            ).fetchone()
        return row is not None and bool(row[0])

    def _release_exclusive(self, connection: _AttestationConnection) -> None:
        if isinstance(connection, _QuarantineAwareConnection) and connection.is_quarantined:
            return
        try:
            with connection.transaction():
                row = connection.execute(
                    "SELECT pg_advisory_unlock(%s)",
                    (self._carrier,),
                ).fetchone()
                if row is None or not bool(row[0]):
                    _fail_closed(connection)
        except PostgresError:
            _fail_closed(connection)


def _postgres_lock_carrier(version: str) -> int:
    return int(_version_lock_carrier(version)[:16], 16) & ((2**63) - 1)


def _fail_closed(connection: _AttestationConnection) -> None:
    try:
        connection.close()
    finally:
        raise IdempotencyLifecycleUnavailable from None


class _PostgresExclusiveGuard:
    __slots__ = ("_attestation", "_entered")

    def __init__(self, attestation: PostgresWriterAttestation) -> None:
        self._attestation = attestation
        self._entered = False

    def __enter__(self) -> None:
        self._attestation._acquire_exclusive()
        self._entered = True

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        if self._entered:
            self._entered = False
            self._attestation._release_exclusive(self._attestation._conn)
