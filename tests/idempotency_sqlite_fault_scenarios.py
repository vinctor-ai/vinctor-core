from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, NoReturn

import pytest
from idempotency_sqlite_fixtures import (
    audit_event,
    configured_executor,
    count_rows,
    invocation,
    outcome,
)

from vinctor_service.idempotency_models import IdempotencyWriteUnavailable
from vinctor_service.sqlite_txn import connect_sqlite

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import CacheableTerminalOutcome


@dataclass(frozen=True, slots=True)
class PhaseTwoFaultOutcome:
    fault: str
    error_type: str
    business_rows: int
    audit_rows: int
    result_rows: int
    nonce_rows: int


def _persisted_outcome(
    database: Path,
    *,
    fault: str,
    error: BaseException,
) -> PhaseTwoFaultOutcome:
    observer = connect_sqlite(database)
    try:
        return PhaseTwoFaultOutcome(
            fault=fault,
            error_type=type(error).__name__,
            business_rows=count_rows(observer, "business_marker"),
            audit_rows=count_rows(observer, "audit_events"),
            result_rows=count_rows(observer, "idempotency_results"),
            nonce_rows=count_rows(observer, "idempotency_cipher_nonces"),
        )
    finally:
        observer.close()


def _mutation(connection, store, event_id: str) -> CacheableTerminalOutcome:
    connection.execute("INSERT INTO business_marker(value) VALUES (1)")
    store.audit_writer.write(audit_event(event_id))
    return outcome()


def exercise_cipher_fault(
    database: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> PhaseTwoFaultOutcome:
    connection, store, executor = configured_executor(database)
    connection.execute("CREATE TABLE business_marker(value INTEGER NOT NULL)")
    connection.commit()
    import vinctor_service.idempotency_sqlite as sqlite_idempotency

    def fail_cipher(**_kwargs) -> NoReturn:
        raise RuntimeError("cipher fault")

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(sqlite_idempotency, "encrypt_response", fail_cipher)
            with pytest.raises(RuntimeError, match="cipher fault") as captured:
                executor.execute(
                    invocation(),
                    lambda: _mutation(connection, store, "evt_cipher_fault"),
                )
    finally:
        connection.close()
    return _persisted_outcome(database, fault="cipher", error=captured.value)


def exercise_result_insert_fault(database: Path) -> PhaseTwoFaultOutcome:
    connection, store, executor = configured_executor(database)
    connection.execute("CREATE TABLE business_marker(value INTEGER NOT NULL)")
    connection.execute(
        "CREATE TRIGGER reject_idempotency_result "
        "BEFORE INSERT ON idempotency_results "
        "BEGIN SELECT RAISE(ABORT, 'result insert fault'); END"
    )
    connection.commit()
    try:
        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            executor.execute(
                invocation(),
                lambda: _mutation(connection, store, "evt_result_fault"),
            )
    finally:
        connection.close()
    return _persisted_outcome(database, fault="result_insert", error=captured.value)


def exercise_business_commit_fault(database: Path) -> PhaseTwoFaultOutcome:
    connection, store, executor = configured_executor(database)
    connection.execute("CREATE TABLE commit_parent(value INTEGER PRIMARY KEY)")
    connection.execute(
        "CREATE TABLE business_marker("
        "value INTEGER NOT NULL, "
        "FOREIGN KEY(value) REFERENCES commit_parent(value) "
        "DEFERRABLE INITIALLY DEFERRED)"
    )
    connection.commit()
    try:
        with pytest.raises(IdempotencyWriteUnavailable) as captured:
            executor.execute(
                invocation(),
                lambda: _mutation(connection, store, "evt_commit_fault"),
            )
    finally:
        connection.close()
    return _persisted_outcome(database, fault="business_commit", error=captured.value)
