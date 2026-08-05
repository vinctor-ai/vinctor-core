from __future__ import annotations

import multiprocessing
import os
from dataclasses import dataclass
from multiprocessing.synchronize import Event as ProcessEvent
from typing import TYPE_CHECKING

from idempotency_postgres_fixtures import (
    configured_postgres_executor,
    invocation,
)

if TYPE_CHECKING:
    from vinctor_service.idempotency_postgres import PostgresIdempotencyStore
    from vinctor_service.postgres_connection import SerializedPostgresConnection


@dataclass(frozen=True, slots=True)
class WorkerConfig:
    dsn: str
    nonce_byte: int
    crash_after_reservation: bool


@dataclass(frozen=True, slots=True)
class WorkerSignals:
    ready: ProcessEvent
    start: ProcessEvent


@dataclass(frozen=True, slots=True)
class PhaseOneProcessOutcome:
    exit_codes: tuple[int | None, ...]
    reserved_slots: int
    nonces: tuple[bytes, ...]
    callback_count: int
    rollback_marker_count: int
    result_count: int
    audit_count: int


def _first_miss_worker(
    config: WorkerConfig,
    signals: WorkerSignals,
) -> None:
    connection, store, _ = configured_postgres_executor(
        config.dsn,
        nonce_factory=lambda size: bytes((config.nonce_byte,)) * size,
    )
    signals.ready.set()
    assert signals.start.wait(timeout=10)

    try:
        store.reserve_nonce(invocation(), now_epoch=store.database_epoch())
        if config.crash_after_reservation:
            os._exit(17)
    finally:
        connection.close()


def _launch_workers(
    dsn: str,
    nonce_bytes: tuple[int, ...],
    *,
    crash_after_reservation: bool,
) -> tuple[int | None, ...]:
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    ready = tuple(context.Event() for _ in nonce_bytes)
    processes = tuple(
        context.Process(
            target=_first_miss_worker,
            args=(
                WorkerConfig(dsn, nonce_byte, crash_after_reservation),
                WorkerSignals(signal, start),
            ),
        )
        for nonce_byte, signal in zip(nonce_bytes, ready, strict=True)
    )
    for process in processes:
        process.start()
    try:
        for signal in ready:
            assert signal.wait(timeout=10)
        start.set()
        for process in processes:
            process.join(timeout=20)
        assert all(not process.is_alive() for process in processes)
        return tuple(process.exitcode for process in processes)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)


def _prepare_observer(
    dsn: str,
) -> tuple[SerializedPostgresConnection, PostgresIdempotencyStore]:
    connection, store, _ = configured_postgres_executor(dsn)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS idempotency_callback_marker(process_id BIGINT NOT NULL)"
    )
    connection.execute(
        "CREATE TABLE IF NOT EXISTS idempotency_rollback_marker(process_id BIGINT NOT NULL)"
    )
    connection.commit()
    return connection, store


def _observe_process_outcome(
    connection: SerializedPostgresConnection,
    store: PostgresIdempotencyStore,
    exit_codes: tuple[int | None, ...],
) -> PhaseOneProcessOutcome:
    state = store.key_version_state("primary")
    nonce_rows = connection.execute(
        "SELECT nonce FROM idempotency_cipher_nonces ORDER BY nonce"
    ).fetchall()
    counts = connection.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM idempotency_callback_marker), "
        "(SELECT COUNT(*) FROM idempotency_rollback_marker), "
        "(SELECT COUNT(*) FROM idempotency_results), "
        "(SELECT COUNT(*) FROM audit_events)"
    ).fetchone()
    assert counts is not None
    connection.rollback()
    return PhaseOneProcessOutcome(
        exit_codes=exit_codes,
        reserved_slots=state.reserved_encryption_slots,
        nonces=tuple(bytes(row[0]) for row in nonce_rows),
        callback_count=int(counts[0]),
        rollback_marker_count=int(counts[1]),
        result_count=int(counts[2]),
        audit_count=int(counts[3]),
    )


def exercise_abrupt_first_misses(dsn: str) -> PhaseOneProcessOutcome:
    connection, store = _prepare_observer(dsn)
    try:
        first = _launch_workers(dsn, (17,), crash_after_reservation=True)
        second = _launch_workers(dsn, (34,), crash_after_reservation=True)
        return _observe_process_outcome(connection, store, first + second)
    finally:
        connection.close()


def exercise_concurrent_first_misses(dsn: str) -> PhaseOneProcessOutcome:
    connection, store = _prepare_observer(dsn)
    try:
        exit_codes = _launch_workers(
            dsn,
            (51, 68),
            crash_after_reservation=False,
        )
        return _observe_process_outcome(connection, store, exit_codes)
    finally:
        connection.close()
