from __future__ import annotations

import base64
import sqlite3
from pathlib import Path
from types import TracebackType
from typing import Any, NoReturn, cast

import pytest
from idempotency_sqlite_fixtures import configured_pool

from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    IdempotencyInvocation,
    IdempotencyProceedToReservation,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_sqlite import (
    SQLiteIdempotencyStore,
    SQLiteIdempotentMutationExecutor,
)
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_pool import SQLiteServicePool
from vinctor_service.sqlite_txn import (
    SerializedSQLiteConnection,
    connect_sqlite,
)


class CommitAcknowledgementLostConnection(sqlite3.Connection):
    fail_next_commit_ack = False

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        result = super().__exit__(exc_type, exc, traceback)
        if exc is None and self.fail_next_commit_ack:
            self.fail_next_commit_ack = False
            raise sqlite3.OperationalError("commit acknowledgement unavailable")
        return result


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


def ambiguous_store() -> tuple[SQLiteIdempotencyStore, SerializedSQLiteConnection]:
    raw = sqlite3.connect(":memory:", factory=CommitAcknowledgementLostConnection)
    connection = SerializedSQLiteConnection(raw)
    store = SQLiteIdempotencyStore(connection, keyring=None)
    cast(CommitAcknowledgementLostConnection, raw).fail_next_commit_ack = True
    return store, connection


def test_commit_exit_failure_is_typed_after_body_completed() -> None:
    store, connection = ambiguous_store()

    with pytest.raises(AmbiguousCommitError), store._transaction():
        connection.execute("CREATE TABLE durable_state (value INTEGER NOT NULL)")

    assert connection.execute("SELECT value FROM durable_state").fetchall() == []
    connection.close()


def test_statement_failure_is_not_mislabeled_as_ambiguous_commit() -> None:
    store, connection = ambiguous_store()

    with pytest.raises(sqlite3.OperationalError, match="no such table"), store._transaction():
        connection.execute("INSERT INTO missing_table VALUES (1)")

    connection.close()


def test_executor_maps_typed_ambiguity_without_running_callback() -> None:
    executor = SQLiteIdempotentMutationExecutor(cast(SQLiteIdempotencyStore, AmbiguousStore()))
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


def test_injected_reporter_quarantines_current_pool_generation(tmp_path: Path) -> None:
    pool = configured_pool(tmp_path / "pool.db", size=1)
    callbacks = 0

    def callback() -> Any:
        nonlocal callbacks
        callbacks += 1
        raise AssertionError

    try:
        with pool.request_scope():
            old = pool.current_context
            executor = SQLiteIdempotentMutationExecutor(
                cast(SQLiteIdempotencyStore, AmbiguousStore()),
                ambiguous_commit_reporter=lambda: pool.quarantine_current_context(old.generation),
            )
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
        with pool.request_scope():
            replacement = pool.current_context

        assert old.healthy is False
        assert replacement.generation > old.generation
        with pytest.raises(sqlite3.ProgrammingError):
            old.connection.execute("SELECT 1")
        assert callbacks == 0
    finally:
        pool.close()


def test_production_pool_automatically_quarantines_ambiguous_generation(
    tmp_path: Path,
) -> None:
    database = tmp_path / "production-pool.db"
    key = base64.b64encode(b"k" * 32).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"primary":"{key}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
        }
    )
    primary = connect_sqlite(
        database,
        check_same_thread=False,
        factory=CommitAcknowledgementLostConnection,
    )
    raw = cast(CommitAcknowledgementLostConnection, primary._connection)
    service = SQLiteV1Service(primary, idempotency_keyring=keyring)
    pool = SQLiteServicePool(
        database,
        primary_connection=primary,
        primary_service=service,
        primary_key_repository=SQLiteLocalKeyRepository(primary),
        size=1,
    )
    callbacks = 0

    def callback() -> Any:
        nonlocal callbacks
        callbacks += 1
        raise AssertionError

    try:
        with pool.request_scope():
            old = pool.current_context
            raw.fail_next_commit_ack = True
            with pytest.raises(IdempotencyWriteUnavailable):
                pool.service.execute_idempotent(
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
        with pool.request_scope():
            replacement = pool.current_context
            replacement_store_connection = replacement.service.idempotency_executor.store.conn

        assert callbacks == 0
        assert old.healthy is False
        assert replacement.generation > old.generation
        assert replacement_store_connection is replacement.connection
        assert replacement.service.shared_state is old.service.shared_state
        with pytest.raises(sqlite3.ProgrammingError):
            old.connection.execute("SELECT 1")
    finally:
        pool.close()
