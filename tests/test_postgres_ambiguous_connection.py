from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import Any, NoReturn

import pytest

from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    IdempotencyInvocation,
    IdempotencyProceedToReservation,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_postgres import PostgresIdempotentMutationExecutor
from vinctor_service.postgres_connection import SerializedPostgresConnection


class TransportError(RuntimeError):
    pass


class Cursor:
    def __init__(self, row: tuple[int, ...] = (1,)) -> None:
        self._row = row

    def fetchone(self) -> tuple[int, ...]:
        return self._row


class Info:
    def __init__(self, connection: PhysicalConnection) -> None:
        self.connection = connection

    @property
    def transaction_status(self) -> int:
        return 0 if self.connection.depth == 0 else 2


class Transaction:
    def __init__(self, connection: PhysicalConnection) -> None:
        self.connection = connection

    def __enter__(self) -> Transaction:
        self.connection.depth += 1
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self.connection.depth -= 1
        if exc is None and self.connection.fail_commit:
            self.connection.fail_commit = False
            raise TransportError("commit acknowledgement unavailable")
        return False


class PhysicalConnection:
    def __init__(
        self,
        name: str,
        *,
        fail_commit: bool = False,
        fail_execute: bool = False,
    ) -> None:
        self.name = name
        self.fail_commit = fail_commit
        self.fail_execute = fail_execute
        self.depth = 0
        self.closed = False
        self.broken = False
        self.statements: list[str] = []
        self.info = Info(self)

    def transaction(self) -> Transaction:
        return Transaction(self)

    def execute(self, statement: str, *args: Any, **kwargs: Any) -> Cursor:
        del args, kwargs
        if self.closed:
            raise TransportError("closed")
        self.statements.append(statement)
        if self.fail_execute:
            self.fail_execute = False
            raise TransportError("statement failed")
        return Cursor()

    def close(self) -> None:
        self.closed = True


def wrapper(
    primary: PhysicalConnection,
    replacements: list[PhysicalConnection],
    *,
    validator: Callable[[Any], None] | None = None,
) -> tuple[SerializedPostgresConnection, list[str]]:
    reconnects: list[str] = []

    def reconnect() -> PhysicalConnection:
        reconnects.append("called")
        return replacements.pop(0)

    return (
        SerializedPostgresConnection(
            primary,
            reconnect=reconnect,
            ambiguous_commit_errors=(TransportError,),
            replacement_validator=validator,
        ),
        reconnects,
    )


def test_commit_exit_transport_failure_is_typed_and_quarantines_without_replay() -> None:
    old = PhysicalConnection("old", fail_commit=True)
    connection, reconnects = wrapper(old, [PhysicalConnection("replacement")])
    emissions: list[str] = []
    old_generation = connection.generation

    with pytest.raises(AmbiguousCommitError), connection.transaction():
        connection.emit_or_defer(lambda: emissions.append("committed"))
        connection.execute("INSERT INTO durable_state VALUES (1)")

    assert connection.generation > old_generation
    assert connection.is_quarantined is True
    assert old.closed is True
    assert old.statements == ["INSERT INTO durable_state VALUES (1)"]
    assert reconnects == []
    assert emissions == []


def test_statement_transport_failure_is_not_mislabeled_as_ambiguous_commit() -> None:
    old = PhysicalConnection("old", fail_execute=True)
    connection, _ = wrapper(old, [])

    with pytest.raises(TransportError, match="statement failed"), connection.transaction():
        connection.execute("UPDATE durable_state SET value = 2")

    assert connection.generation == 1
    assert connection.is_quarantined is False
    assert old.closed is False


def test_replacement_is_published_only_after_probe_and_validator_pass() -> None:
    old = PhysicalConnection("old", fail_commit=True)
    rejected = PhysicalConnection("rejected")
    accepted = PhysicalConnection("accepted")
    validations: list[str] = []

    def validate(candidate: PhysicalConnection) -> None:
        validations.append(candidate.name)
        if candidate is rejected:
            raise RuntimeError("schema incompatible")

    connection, reconnects = wrapper(old, [rejected, accepted], validator=validate)
    with pytest.raises(AmbiguousCommitError), connection.transaction():
        connection.execute("INSERT INTO durable_state VALUES (1)")

    with pytest.raises(RuntimeError, match="schema incompatible"):
        connection.execute("SELECT application_state")
    assert rejected.closed is True
    assert connection.is_quarantined is True
    assert reconnects == ["called"]

    assert connection.execute("SELECT application_state").fetchone() == (1,)
    assert connection.is_quarantined is False
    assert reconnects == ["called", "called"]
    assert validations == ["rejected", "accepted"]
    assert accepted.statements == ["SELECT 1", "SELECT application_state"]


def test_stale_quarantine_cannot_close_the_published_generation() -> None:
    old = PhysicalConnection("old", fail_commit=True)
    replacement = PhysicalConnection("replacement")
    connection, _ = wrapper(old, [replacement])
    old_generation = connection.generation
    with pytest.raises(AmbiguousCommitError), connection.transaction():
        connection.execute("INSERT INTO durable_state VALUES (1)")
    connection.execute("SELECT 1")

    assert connection.quarantine_after_ambiguous_commit(old_generation) is False
    assert replacement.closed is False


def test_fresh_authoritative_read_uses_post_quarantine_generation_transaction() -> None:
    old = PhysicalConnection("old", fail_commit=True)
    replacement = PhysicalConnection("replacement")
    connection, _ = wrapper(old, [replacement])
    old_generation = connection.generation
    with pytest.raises(AmbiguousCommitError), connection.transaction():
        connection.execute("INSERT INTO durable_state VALUES (1)")

    with connection.fresh_authoritative_read(after_generation=old_generation):
        row = connection.execute("SELECT authoritative_state").fetchone()

    assert row == (1,)
    assert connection.generation > old_generation
    assert replacement.statements == ["SELECT 1", "SELECT authoritative_state"]


def test_barrier_recovery_uses_compatible_candidate_without_publishing_it_ready() -> None:
    old = PhysicalConnection("old", fail_commit=True)
    replacement = PhysicalConnection("replacement")
    compatibility_checks: list[str] = []
    readiness_checks: list[str] = []

    def compatible(candidate: PhysicalConnection) -> None:
        compatibility_checks.append(candidate.name)

    def not_operationally_ready(candidate: PhysicalConnection) -> None:
        readiness_checks.append(candidate.name)
        raise RuntimeError("active version is write-disabled")

    connection, _ = wrapper(old, [replacement], validator=compatible)
    connection.add_readiness_validator(not_operationally_ready)
    old_generation = connection.generation
    with pytest.raises(AmbiguousCommitError), connection.transaction():
        connection.execute("UPDATE durable_barrier")

    with connection.fresh_authoritative_recovery(after_generation=old_generation) as authority:
        assert authority.execute("SELECT durable_barrier").fetchone() == (1,)

    assert compatibility_checks == ["replacement"]
    assert readiness_checks == []
    assert replacement.closed is True
    assert connection.is_quarantined is True
    assert connection.is_ready is False


def test_reservation_ambiguity_maps_to_coarse_unavailable_without_callback() -> None:
    class AmbiguousStore:
        def database_epoch(self) -> int:
            return 100

        def lookup(
            self,
            invocation: IdempotencyInvocation,
            *,
            now_epoch: int,
        ) -> IdempotencyProceedToReservation:
            del invocation, now_epoch
            return IdempotencyProceedToReservation()

        def reserve_nonce(
            self,
            invocation: IdempotencyInvocation,
            *,
            now_epoch: int,
        ) -> NoReturn:
            del invocation, now_epoch
            raise AmbiguousCommitError

    executor = PostgresIdempotentMutationExecutor(AmbiguousStore())
    invocation = IdempotencyInvocation(
        workspace_id="ws",
        principal="agent:a",
        operation="grant.issue.v1",
        key_hash=b"k" * 32,
        request_fingerprint=b"f" * 32,
        max_terminal_ttl_seconds=86_400,
    )
    callbacks = 0

    def callback() -> Any:
        nonlocal callbacks
        callbacks += 1
        raise AssertionError

    with pytest.raises(IdempotencyWriteUnavailable) as captured:
        executor.execute(invocation, callback)

    assert str(captured.value) == "idempotency unavailable"
    assert callbacks == 0
