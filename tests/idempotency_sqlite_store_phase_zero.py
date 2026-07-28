from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal

from idempotency_sqlite_fixtures import (
    configured_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_sqlite_store_models import (
    CompletedResultSeed,
    PhaseZeroFailureOutcome,
    ReplayOutcome,
)
from idempotency_sqlite_store_seed import _seed_completed_result

from vinctor_service.idempotency_models import (
    IdempotencyConflict,
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
)

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
    )

def exercise_phase_zero_replay(database: Path) -> ReplayOutcome:
    connection, store, executor = configured_executor(database)
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome()

    try:
        request, terminal = _seed_completed_result(connection, store)
        before = count_rows(connection, "idempotency_cipher_nonces")
        replay = executor.execute(request, mutation)
        after = count_rows(connection, "idempotency_cipher_nonces")
        return ReplayOutcome(replay == terminal.response, calls, before, after)
    finally:
        connection.close()

def exercise_phase_zero_observation_replay(database: Path) -> ReplayOutcome:
    connection, store, executor = configured_executor(database)
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome()

    try:
        terminal = outcome(error_code="forbidden", decision="deny")
        request, _ = _seed_completed_result(
            connection,
            store,
            CompletedResultSeed(terminal, store.database_epoch()),
        )
        before = count_rows(connection, "idempotency_cipher_nonces")
        replay = executor.execute(request, mutation)
        after = count_rows(connection, "idempotency_cipher_nonces")
        return ReplayOutcome(replay == terminal.response, calls, before, after)
    finally:
        connection.close()

def exercise_phase_zero_conflict(database: Path) -> PhaseZeroFailureOutcome:
    connection, store, executor = configured_executor(database)
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome()

    try:
        _seed_completed_result(connection, store)
        before = count_rows(connection, "idempotency_cipher_nonces")
        try:
            executor.execute(invocation(fingerprint=b"x" * 32), mutation)
        except IdempotencyConflict:
            typed_error = True
        else:
            typed_error = False
        return PhaseZeroFailureOutcome(
            typed_error=typed_error,
            callback_count=calls,
            reservations_before=before,
            reservations_after=count_rows(connection, "idempotency_cipher_nonces"),
            result_count=count_rows(connection, "idempotency_results"),
        )
    finally:
        connection.close()

def exercise_phase_zero_unavailable(
    database: Path,
    fault: Literal[
        "corrupt",
        "expiry_metadata",
        "fingerprint_metadata",
        "unknown_key",
    ],
) -> PhaseZeroFailureOutcome:
    connection, store, executor = configured_executor(database)
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome()

    try:
        request, _ = _seed_completed_result(connection, store)
        match fault:
            case "corrupt":
                connection.execute(
                    "UPDATE idempotency_results SET response_ciphertext = ?",
                    (b"x" * 16,),
                )
            case "unknown_key":
                connection.execute(
                    "INSERT INTO idempotency_cipher_key_versions "
                    "(version_label, key_commitment, reserved_encryption_slots, "
                    "first_seen_epoch) VALUES ('unknown', ?, 0, 0)",
                    (b"u" * 32,),
                )
                connection.execute("UPDATE idempotency_results SET cipher_key_version = 'unknown'")
            case "expiry_metadata":
                connection.execute(
                    "UPDATE idempotency_results "
                    "SET created_at_epoch = 0, expires_at_epoch = 1"
                )
            case "fingerprint_metadata":
                connection.execute(
                    "UPDATE idempotency_results SET request_fingerprint = ?",
                    (b"x" * 32,),
                )
        connection.commit()
        before = count_rows(connection, "idempotency_cipher_nonces")
        try:
            executor.execute(request, mutation)
        except IdempotencyResultUnavailable:
            typed_error = True
        else:
            typed_error = False
        return PhaseZeroFailureOutcome(
            typed_error=typed_error,
            callback_count=calls,
            reservations_before=before,
            reservations_after=count_rows(connection, "idempotency_cipher_nonces"),
            result_count=count_rows(connection, "idempotency_results"),
        )
    finally:
        connection.close()

def exercise_phase_zero_expired(database: Path) -> PhaseZeroFailureOutcome:
    connection, store, executor = configured_executor(database)
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome()

    try:
        _seed_completed_result(
            connection,
            store,
            CompletedResultSeed(outcome(), 0),
        )
        before = count_rows(connection, "idempotency_cipher_nonces")
        try:
            executor.execute(invocation(fingerprint=b"x" * 32), mutation)
        except IdempotencyWriteUnavailable:
            typed_error = True
        else:
            typed_error = False
        return PhaseZeroFailureOutcome(
            typed_error=typed_error,
            callback_count=calls,
            reservations_before=before,
            reservations_after=count_rows(connection, "idempotency_cipher_nonces"),
            result_count=count_rows(connection, "idempotency_results"),
        )
    finally:
        connection.close()
