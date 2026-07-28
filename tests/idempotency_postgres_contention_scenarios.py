from __future__ import annotations

import multiprocessing
from dataclasses import dataclass
from multiprocessing.synchronize import Event as ProcessEvent
from queue import SimpleQueue
from threading import Barrier, Thread
from typing import TYPE_CHECKING

from idempotency_postgres_fixtures import (
    configured_postgres_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_postgres_phase01_results import (
    CompletedResultSeed,
    seed_completed_result,
)

from vinctor_service.postgres import connect_postgres, init_postgres_schema

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import CacheableTerminalOutcome
    from vinctor_service.idempotency_postgres import PostgresIdempotencyStore


@dataclass(frozen=True, slots=True)
class ProcessRaceOutcome:
    exit_codes: tuple[int | None, ...]
    callback_count: int
    result_count: int


@dataclass(frozen=True, slots=True)
class SlotContentionOutcome:
    threads_finished: bool
    accepted: int
    rejected: int
    reserved_slots: int
    nonce_count: int
    disabled_reason: str | None


@dataclass(frozen=True, slots=True)
class GcContentionOutcome:
    deleted: int
    remaining: int
    locked_row_survived: bool


def _process_race_worker(
    dsn: str,
    ready: ProcessEvent,
    start: ProcessEvent,
) -> None:
    connection, _, executor = configured_postgres_executor(dsn)
    ready.set()
    assert start.wait(timeout=10)

    def mutation() -> CacheableTerminalOutcome:
        connection.execute(
            "INSERT INTO idempotency_callback_marker(process_id) VALUES (pg_backend_pid())"
        )
        return outcome()

    try:
        executor.execute(invocation(), mutation)
    finally:
        connection.close()


def exercise_postgres_process_race(dsn: str) -> ProcessRaceOutcome:
    observer = connect_postgres(dsn)
    init_postgres_schema(observer)
    observer.execute(
        "CREATE TABLE IF NOT EXISTS idempotency_callback_marker(process_id BIGINT NOT NULL)"
    )
    observer.commit()
    context = multiprocessing.get_context("spawn")
    ready = (context.Event(), context.Event())
    start = context.Event()
    processes = tuple(
        context.Process(target=_process_race_worker, args=(dsn, signal, start)) for signal in ready
    )
    for process in processes:
        process.start()
    try:
        for signal in ready:
            assert signal.wait(timeout=10)
        start.set()
        for process in processes:
            process.join(timeout=20)
        return ProcessRaceOutcome(
            exit_codes=tuple(process.exitcode for process in processes),
            callback_count=count_rows(observer, "idempotency_callback_marker"),
            result_count=count_rows(observer, "idempotency_results"),
        )
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        observer.close()


def _reserve_at_hard_limit(
    store: PostgresIdempotencyStore,
    barrier: Barrier,
    outcomes: SimpleQueue[bool],
    now_epoch: int,
) -> None:
    assert barrier.wait(timeout=10) in (0, 1)
    try:
        store.reserve_nonce(invocation(), now_epoch=now_epoch)
    except RuntimeError:
        outcomes.put(False)
    else:
        outcomes.put(True)


def exercise_postgres_slot_contention(dsn: str) -> SlotContentionOutcome:
    first_connection, first_store, _ = configured_postgres_executor(dsn)
    second_connection, second_store, _ = configured_postgres_executor(dsn)
    first_connection.execute(
        "UPDATE idempotency_cipher_key_versions "
        "SET reserved_encryption_slots = %s WHERE version_label = %s",
        ((2**24) - 1, "primary"),
    )
    first_connection.commit()
    now_epoch = first_store.database_epoch()
    barrier = Barrier(2)
    outcomes: SimpleQueue[bool] = SimpleQueue()
    threads = (
        Thread(
            target=_reserve_at_hard_limit,
            args=(first_store, barrier, outcomes, now_epoch),
        ),
        Thread(
            target=_reserve_at_hard_limit,
            args=(second_store, barrier, outcomes, now_epoch),
        ),
    )
    for thread in threads:
        thread.start()
    try:
        for thread in threads:
            thread.join(timeout=15)
        threads_finished = all(not thread.is_alive() for thread in threads)
        assert threads_finished
        observations = (outcomes.get(), outcomes.get())
        state = first_store.key_version_state("primary")
        return SlotContentionOutcome(
            threads_finished=threads_finished,
            accepted=observations.count(True),
            rejected=observations.count(False),
            reserved_slots=state.reserved_encryption_slots,
            nonce_count=count_rows(first_connection, "idempotency_cipher_nonces"),
            disabled_reason=state.write_disabled_reason,
        )
    finally:
        first_connection.close()
        second_connection.close()


def exercise_postgres_skip_locked_gc(dsn: str) -> GcContentionOutcome:
    connection, store, _ = configured_postgres_executor(dsn)
    locker = connect_postgres(dsn)
    init_postgres_schema(locker)
    now_epoch = store.database_epoch()
    for value in range(101):
        request = invocation(key_hash=value.to_bytes(32, "big"))
        seed_completed_result(
            connection,
            store,
            CompletedResultSeed(
                request,
                outcome().response,
                now_epoch - 2,
                now_epoch - 1,
            ),
        )
    connection.execute("SET lock_timeout = '500ms'")
    connection.commit()
    try:
        with locker.transaction():
            locked_row = locker.execute(
                "SELECT key_hash FROM idempotency_results ORDER BY key_hash LIMIT 1 FOR UPDATE"
            ).fetchone()
            assert locked_row is not None
            deleted = store.gc_expired_results(limit=100)
            remaining_rows = connection.execute(
                "SELECT key_hash FROM idempotency_results"
            ).fetchall()
            return GcContentionOutcome(
                deleted=deleted,
                remaining=len(remaining_rows),
                locked_row_survived=(
                    len(remaining_rows) == 1 and bytes(remaining_rows[0][0]) == bytes(locked_row[0])
                ),
            )
    finally:
        locker.close()
        connection.close()
