from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from threading import Barrier

from idempotency_sqlite_fixtures import (
    configured_pool,
    count_rows,
    invocation,
    outcome,
)

from vinctor_service.idempotency_models import CacheableTerminalOutcome
from vinctor_service.sqlite_txn import SerializedSQLiteConnection


@dataclass(frozen=True, slots=True)
class SharedPoolOutcome:
    distinct_connections: int
    distinct_keyrings: int
    connection_bound_executors: int
    callback_count: int


@dataclass(frozen=True, slots=True)
class QuarantineOutcome:
    old_generation: int
    replacement_generation: int
    old_connection_closed: bool


@dataclass(frozen=True, slots=True)
class RebuildOutcome:
    connection_rebuilt: bool
    service_rebuilt: bool
    keys_rebuilt: bool
    process_state_shared: bool


@dataclass(frozen=True, slots=True)
class ReplacementFailureOutcome:
    raised: bool
    capacity: int
    ready: bool


@dataclass(frozen=True, slots=True)
class ShutdownOutcome:
    old_close_count: int
    replacement_close_count: int


@dataclass(frozen=True, slots=True)
class BarrierOutcome:
    write_disabled: bool
    result_count: int


def exercise_shared_pool(database: Path) -> SharedPoolOutcome:
    pool = configured_pool(database)
    barrier = Barrier(2)

    def worker(key_hash: bytes) -> tuple[int, int, bool, int]:
        callback_count = 0

        def callback() -> CacheableTerminalOutcome:
            nonlocal callback_count
            callback_count += 1
            return outcome()

        with pool.request_scope():
            context = pool.current_context
            barrier.wait(timeout=5)
            context.service.execute_idempotent(
                invocation(key_hash=key_hash),
                callback,
            )
            return (
                id(context.connection),
                id(context.service.shared_state.idempotency_keyring),
                context.service.idempotency_executor.store.conn is context.connection,
                callback_count,
            )

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            observations = tuple(executor.map(worker, (b"a" * 32, b"b" * 32)))
        return SharedPoolOutcome(
            distinct_connections=len({item[0] for item in observations}),
            distinct_keyrings=len({item[1] for item in observations}),
            connection_bound_executors=sum(item[2] for item in observations),
            callback_count=sum(item[3] for item in observations),
        )
    finally:
        pool.close()


def exercise_quarantine(database: Path) -> QuarantineOutcome:
    pool = configured_pool(database, size=1)
    try:
        with pool.request_scope():
            old = pool.current_context
            pool.quarantine_current_context(old.generation)
        with pool.request_scope():
            replacement = pool.current_context
        try:
            old.connection.execute("SELECT 1")
        except sqlite3.ProgrammingError:
            old_connection_closed = True
        else:
            old_connection_closed = False
        return QuarantineOutcome(
            old_generation=old.generation,
            replacement_generation=replacement.generation,
            old_connection_closed=old_connection_closed,
        )
    finally:
        pool.close()


def exercise_rebuild(database: Path) -> RebuildOutcome:
    pool = configured_pool(database, size=1)
    try:
        with pool.request_scope():
            old = pool.current_context
            pool.quarantine_current_context(old.generation)
        with pool.request_scope():
            new = pool.current_context
        return RebuildOutcome(
            connection_rebuilt=new.connection is not old.connection,
            service_rebuilt=new.service is not old.service,
            keys_rebuilt=new.key_repository is not old.key_repository,
            process_state_shared=new.service.shared_state is old.service.shared_state,
        )
    finally:
        pool.close()


def exercise_replacement_failure(database: Path) -> ReplacementFailureOutcome:
    def fail_replacement() -> SerializedSQLiteConnection:
        raise RuntimeError("replacement fault")

    pool = configured_pool(
        database,
        size=1,
        connection_factory=fail_replacement,
    )
    try:
        try:
            with pool.request_scope():
                context = pool.current_context
                pool.quarantine_current_context(context.generation)
        except RuntimeError:
            raised = True
        else:
            raised = False
        return ReplacementFailureOutcome(
            raised=raised,
            capacity=pool.capacity,
            ready=pool.is_ready(),
        )
    finally:
        pool.close()


def exercise_shutdown(database: Path) -> ShutdownOutcome:
    closed: list[int] = []
    original_close = SerializedSQLiteConnection.close

    def record_close(connection: SerializedSQLiteConnection) -> None:
        closed.append(id(connection))
        original_close(connection)

    SerializedSQLiteConnection.close = record_close
    try:
        pool = configured_pool(database, size=1)
        with pool.request_scope():
            old = pool.current_context
            pool.quarantine_current_context(old.generation)
        with pool.request_scope():
            replacement = pool.current_context
        pool.close()
        pool.close()
        return ShutdownOutcome(
            old_close_count=closed.count(id(old.connection)),
            replacement_close_count=closed.count(id(replacement.connection)),
        )
    finally:
        SerializedSQLiteConnection.close = original_close


def exercise_barrier_recovery(database: Path) -> BarrierOutcome:
    from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore

    pool = configured_pool(database, size=1)
    try:
        pool.complete_write_disable_barrier_with_fresh_authority(version="primary")
        with pool.request_scope():
            context = pool.current_context
            store = SQLiteIdempotencyStore(
                context.connection,
                keyring=context.service.shared_state.idempotency_keyring,
            )
            state = store.key_version_state("primary")
            result_count = count_rows(context.connection, "idempotency_results")
        return BarrierOutcome(
            write_disabled=state.write_disabled_epoch is not None,
            result_count=result_count,
        )
    finally:
        pool.close()
