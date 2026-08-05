from __future__ import annotations

import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Protocol, TypeAlias

import pytest
from psycopg import OperationalError

from vinctor_service import idempotency_lifecycle_postgres_recovery as recovery
from vinctor_service.idempotency_keyring import IdempotencyKeyring, load_idempotency_keyring
from vinctor_service.idempotency_lifecycle import IdempotencyLifecycleUnavailable
from vinctor_service.idempotency_lifecycle_postgres_lock import (
    PostgresWriterAttestation,
)
from vinctor_service.postgres_connection import SerializedPostgresConnection

DatabaseValue: TypeAlias = str | int | bool | bytes | None


class _Result(Protocol):
    def fetchone(self) -> Sequence[DatabaseValue] | None: ...


class _RawAuthority(Protocol):
    def execute(
        self,
        query: str,
        params: Sequence[DatabaseValue] = (),
    ) -> _Result: ...


class _FakeResult:
    def __init__(self, row: Sequence[DatabaseValue] | None) -> None:
        self._row = row

    def fetchone(self) -> Sequence[DatabaseValue] | None:
        return self._row

    def fetchall(self) -> Sequence[Sequence[DatabaseValue]]:
        return ()


class _FakeAuthority:
    def execute(
        self,
        query: str,
        params: Sequence[DatabaseValue] = (),
    ) -> _FakeResult:
        del params
        if "drain_completed_epoch, retired_epoch" in query:
            return _FakeResult([1_699_000_000, None])
        if "drain_completed_epoch" in query:
            return _FakeResult([1_699_000_000])
        raise AssertionError(f"unexpected query: {query}")


def _keyring() -> IdempotencyKeyring:
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (
                '{"old":"b29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb28=",'
                '"replacement":"cnJycnJycnJycnJycnJycnJycnJycnJycnJycnJycnI="}'
            ),
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "replacement",
        }
    )
    assert keyring is not None
    return keyring


class _RuntimeFailureConnection(SerializedPostgresConnection):
    def __init__(self) -> None:
        pass

    @contextmanager
    def fresh_authoritative_recovery(
        self,
        *,
        after_generation: int,
    ) -> Iterator[_RawAuthority]:
        del after_generation
        raise RuntimeError("sentinel recovery failure")
        yield _FakeAuthority()


class _UnlockFailureConnection:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.is_quarantined = False
        self.closed = False

    def add_replacement_validator(
        self,
        validator: Callable[[_RawAuthority], None],
    ) -> None:
        del validator

    @contextmanager
    def transaction(self) -> Iterator[None]:
        yield

    def execute(
        self,
        query: str,
        params: Sequence[DatabaseValue] = (),
    ) -> _FakeResult:
        del params
        if "pg_advisory_unlock_shared" in query:
            raise OperationalError("forced unlock failure")
        return _FakeResult([True])

    def close(self) -> None:
        self.closed = True


def test_postgres_recovery_adapter_decodes_rows_before_domain_use() -> None:
    # Given a raw driver authority returning sequence-shaped database rows.
    adapter_type = getattr(recovery, "_RecoveryAuthorityAdapter", None)
    assert adapter_type is not None
    raw: _RawAuthority = _FakeAuthority()
    adapter = adapter_type(raw)

    # When the recovery boundary reads each lifecycle state shape.
    drain = adapter.drain_state("old")
    retirement = adapter.retirement_state("old")

    # Then domain code receives named values rather than positional tuple bags.
    assert drain is not None
    assert drain.drain_completed_epoch == 1_699_000_000
    assert retirement is not None
    assert retirement.drain_completed_epoch == 1_699_000_000
    assert retirement.retired_epoch is None


def test_postgres_recovery_does_not_translate_unowned_runtime_errors() -> None:
    lifecycle_recovery = recovery.PostgresLifecycleRecovery(
        _RuntimeFailureConnection(),
        _keyring(),
    )
    with pytest.raises(RuntimeError, match="sentinel recovery failure"):
        lifecycle_recovery.drain("old", generation=1)


def test_postgres_shared_unlock_failure_closes_the_connection() -> None:
    connection = _UnlockFailureConnection()
    attestation = PostgresWriterAttestation(connection, "old")
    attestation.register()

    with pytest.raises(IdempotencyLifecycleUnavailable):
        attestation.close()

    assert connection.closed is True
