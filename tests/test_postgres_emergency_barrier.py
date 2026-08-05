from __future__ import annotations

import base64
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from threading import RLock
from typing import Any, cast

import pytest

from vinctor_service.idempotency_keyring import (
    IdempotencyKeyring,
    load_idempotency_keyring,
)
from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    IdempotencyInvocation,
    IdempotencyProceedToReservation,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_postgres import (
    PostgresIdempotencyStore,
    PostgresIdempotentMutationExecutor,
)
from vinctor_service.idempotency_storage import HARD_SLOT_LIMIT
from vinctor_service.postgres_connection import SerializedPostgresConnection


class Cursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class EmergencyBarrierConnection:
    def __init__(self, mode: str, *, commit_happened: bool) -> None:
        self.mode = mode
        self.commit_happened = commit_happened
        self.lock = RLock()
        self.info = type("Info", (), {"transaction_status": 0})()
        self.generation = 1
        self.is_quarantined = False
        self.slots = HARD_SLOT_LIMIT if mode == "hard_limit" else 7
        self.nonces = {b"n" * 12} if mode == "nonce_collision" else set()
        self.write_disabled_epoch: int | None = None
        self.write_disabled_reason: str | None = None
        self.fail_barrier_ack = True
        self.fresh_recoveries = 0
        self.results = 0
        self.audits = 0
        self._barrier_written = False
        self.compatibility_validators: list[Callable[[Any], None]] = []
        self.readiness_validators: list[Callable[[Any], None]] = []

    def add_replacement_validator(self, validator: Callable[[Any], None]) -> None:
        self.compatibility_validators.append(validator)

    def add_readiness_validator(self, validator: Callable[[Any], None]) -> None:
        self.readiness_validators.append(validator)

    @contextmanager
    def transaction(self) -> Iterator[None]:
        snapshot = (
            self.slots,
            set(self.nonces),
            self.write_disabled_epoch,
            self.write_disabled_reason,
        )
        self.info.transaction_status = 2
        self._barrier_written = False
        try:
            yield
        except BaseException:
            self._restore(snapshot)
            self.info.transaction_status = 0
            raise
        self.info.transaction_status = 0
        if self._barrier_written and self.fail_barrier_ack:
            self.fail_barrier_ack = False
            if not self.commit_happened:
                self._restore(snapshot)
            self.generation += 1
            self.is_quarantined = True
            raise AmbiguousCommitError

    @contextmanager
    def fresh_authoritative_recovery(self, *, after_generation: int) -> Iterator[Any]:
        assert self.generation > after_generation
        self.fresh_recoveries += 1
        with self.transaction():
            yield self

    def execute(
        self,
        query: str,
        params: tuple[str | bytes | int, ...] | None = None,
    ) -> Cursor:
        if "SET reserved_encryption_slots = reserved_encryption_slots + 1" in query:
            if self.write_disabled_epoch is not None or self.slots >= HARD_SLOT_LIMIT:
                return Cursor(None)
            self.slots += 1
            return Cursor((self.slots,))
        if "SET soft_limit_reported_epoch" in query:
            return Cursor(None)
        if "INSERT INTO idempotency_cipher_nonces" in query:
            assert params is not None
            nonce = cast(bytes, params[2])
            if nonce in self.nonces:
                return Cursor(None)
            self.nonces.add(nonce)
            return Cursor((nonce,))
        if "SELECT reserved_encryption_slots" in query:
            return Cursor(
                (
                    self.slots,
                    1,
                    None,
                    self.write_disabled_epoch,
                    self.write_disabled_reason,
                    None,
                    None,
                )
            )
        if "SELECT write_disabled_epoch, write_disabled_reason" in query:
            return Cursor((self.write_disabled_epoch, self.write_disabled_reason))
        if "SET write_disabled_epoch = COALESCE" in query:
            assert params is not None
            if self.write_disabled_epoch is None:
                self.write_disabled_epoch = cast(int, params[0])
                self.write_disabled_reason = cast(str, params[1])
            self._barrier_written = True
            return Cursor(None)
        raise AssertionError(query)

    def _restore(
        self,
        snapshot: tuple[int, set[bytes], int | None, str | None],
    ) -> None:
        self.slots, nonces, self.write_disabled_epoch, self.write_disabled_reason = snapshot
        self.nonces = set(nonces)


class EmergencyBarrierStore(PostgresIdempotencyStore):
    def _register_keyring(self) -> None:
        return

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


def keyring() -> IdempotencyKeyring:
    key = base64.b64encode(b"k" * 32).decode("ascii")
    result = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    assert result is not None
    return result


@pytest.mark.parametrize(
    ("mode", "reason"),
    (("nonce_collision", "nonce_collision"), ("hard_limit", "hard_limit")),
)
@pytest.mark.parametrize("commit_happened", (True, False))
def test_emergency_barrier_recovers_through_fresh_authority(
    mode: str,
    reason: str,
    commit_happened: bool,
) -> None:
    connection = EmergencyBarrierConnection(mode, commit_happened=commit_happened)
    initial_slots = connection.slots
    initial_nonces = set(connection.nonces)
    store = EmergencyBarrierStore(
        cast(SerializedPostgresConnection, connection),
        keyring=keyring(),
        nonce_factory=lambda size: b"n" * size,
    )
    executor = PostgresIdempotentMutationExecutor(store)
    callbacks = 0

    def callback() -> Any:
        nonlocal callbacks
        callbacks += 1
        raise AssertionError

    with pytest.raises(IdempotencyWriteUnavailable):
        executor.execute(
            IdempotencyInvocation(
                workspace_id="ws",
                principal="agent:a",
                operation="grant.issue.v1",
                key_hash=b"k" * 32,
                request_fingerprint=b"f" * 32,
                max_terminal_ttl_seconds=86_400,
            ),
            callback,
        )

    assert connection.fresh_recoveries == 1
    assert connection.write_disabled_epoch == 100
    assert connection.write_disabled_reason == reason
    assert connection.slots == initial_slots
    assert connection.nonces == initial_nonces
    assert connection.generation == 2
    assert connection.is_quarantined is True
    assert callbacks == 0
    assert connection.results == 0
    assert connection.audits == 0
