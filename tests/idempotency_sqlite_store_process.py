from __future__ import annotations

import multiprocessing
import os
from multiprocessing.connection import Connection
from multiprocessing.synchronize import Event as ProcessEvent
from pathlib import Path
from typing import TYPE_CHECKING

from idempotency_sqlite_fixtures import (
    configured_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_sqlite_store_models import (
    FirstMissRaceOutcome,
    ProcessRaceOutcome,
    ReservationOutcome,
)

from vinctor_service.idempotency_models import (
    IdempotencyWriteUnavailable,
)
from vinctor_service.sqlite_txn import connect_sqlite

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
    )

def _reserve_then_crash(database: str, sender: Connection) -> None:
    connection, store, _ = configured_executor(Path(database))
    reservation = store.reserve_nonce(invocation(), now_epoch=100)
    sender.send_bytes(reservation.nonce)
    sender.close()
    os._exit(17)

def exercise_durable_reservation(database: Path) -> ReservationOutcome:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_reserve_then_crash, args=(str(database), sender))
    process.start()
    sender.close()
    assert receiver.poll(5)
    reserved_nonce = receiver.recv_bytes()
    receiver.close()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
    assert process.exitcode == 17
    reopened = connect_sqlite(database)
    try:
        row = reopened.execute("SELECT nonce FROM idempotency_cipher_nonces").fetchone()
        assert row is not None
        return ReservationOutcome(
            exit_code=process.exitcode,
            reservation_count=count_rows(reopened, "idempotency_cipher_nonces"),
            nonce_matches=reserved_nonce == row[0],
        )
    finally:
        reopened.close()

def _first_miss_worker(
    database: str,
    ready: ProcessEvent,
    start: ProcessEvent,
) -> None:
    connection, _, executor = configured_executor(Path(database))
    ready.set()
    assert start.wait(timeout=5)

    def mutation() -> CacheableTerminalOutcome:
        connection.execute("INSERT INTO idempotency_callback_marker(value) VALUES (1)")
        return outcome()

    try:
        executor.execute(invocation(), mutation)
    except IdempotencyWriteUnavailable:
        pass
    finally:
        connection.close()

def exercise_concurrent_first_misses(database: Path) -> FirstMissRaceOutcome:
    connection, _, _ = configured_executor(database)
    connection.execute("CREATE TABLE idempotency_callback_marker(value INTEGER NOT NULL)")
    connection.commit()
    connection.close()
    context = multiprocessing.get_context("spawn")
    ready = (context.Event(), context.Event())
    start = context.Event()
    processes = tuple(
        context.Process(target=_first_miss_worker, args=(str(database), signal, start))
        for signal in ready
    )
    for process in processes:
        process.start()
    for signal in ready:
        assert signal.wait(timeout=5)
    start.set()
    for process in processes:
        process.join(timeout=10)
    reopened = connect_sqlite(database)
    try:
        distinct_row = reopened.execute(
            "SELECT COUNT(DISTINCT hex(nonce)) FROM idempotency_cipher_nonces"
        ).fetchone()
        assert distinct_row is not None
        return FirstMissRaceOutcome(
            exit_codes=tuple(process.exitcode for process in processes),
            callback_count=count_rows(reopened, "idempotency_callback_marker"),
            result_count=count_rows(reopened, "idempotency_results"),
            reservation_count=count_rows(reopened, "idempotency_cipher_nonces"),
            distinct_nonce_count=int(distinct_row[0]),
        )
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        reopened.close()

def _race_worker(
    database: str,
    ready: ProcessEvent,
    start: ProcessEvent,
) -> None:
    connection, _, executor = configured_executor(Path(database))
    ready.set()
    assert start.wait(timeout=5)

    def mutation() -> CacheableTerminalOutcome:
        connection.execute("INSERT INTO idempotency_callback_marker(value) VALUES (1)")
        return outcome()

    try:
        executor.execute(invocation(), mutation)
    finally:
        connection.close()

def exercise_process_race(database: Path) -> ProcessRaceOutcome:
    connection, _, _ = configured_executor(database)
    connection.execute("CREATE TABLE idempotency_callback_marker(value INTEGER NOT NULL)")
    connection.commit()
    connection.close()
    context = multiprocessing.get_context("spawn")
    ready = (context.Event(), context.Event())
    start = context.Event()
    processes = tuple(
        context.Process(target=_race_worker, args=(str(database), signal, start))
        for signal in ready
    )
    for process in processes:
        process.start()
    for signal in ready:
        assert signal.wait(timeout=5)
    start.set()
    for process in processes:
        process.join(timeout=10)
    reopened = connect_sqlite(database)
    try:
        return ProcessRaceOutcome(
            exit_codes=tuple(process.exitcode for process in processes),
            callback_count=count_rows(reopened, "idempotency_callback_marker"),
            result_count=count_rows(reopened, "idempotency_results"),
        )
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
        reopened.close()
