from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from idempotency_sqlite_fixtures import (
    configured_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_sqlite_store_models import (
    CollisionOutcome,
    CompletedResultSeed,
    GcOutcome,
    LoserOutcome,
    SlotBoundaryOutcome,
)
from idempotency_sqlite_store_seed import _seed_completed_result

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
    )

def exercise_loser_replay(database: Path) -> LoserOutcome:
    connection, _, executor = configured_executor(database)
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome()

    try:
        executor.execute(invocation(), mutation)
        executor.execute(invocation(), mutation)
        return LoserOutcome(
            callback_count=calls,
            result_count=count_rows(connection, "idempotency_results"),
            reservation_count=count_rows(connection, "idempotency_cipher_nonces"),
        )
    finally:
        connection.close()

def exercise_nonce_collision(database: Path) -> CollisionOutcome:
    nonce = b"n" * 12
    connection, store, _ = configured_executor(
        database,
        nonce_factory=lambda _size: nonce,
    )
    try:
        store.reserve_nonce(invocation(), now_epoch=100)
        try:
            store.reserve_nonce(invocation(), now_epoch=101)
        except RuntimeError:
            raised = True
        else:
            raised = False
        state = store.key_version_state("primary")
        return CollisionOutcome(
            raised=raised,
            reserved_slots=state.reserved_encryption_slots,
            disabled_reason=state.write_disabled_reason,
        )
    finally:
        connection.close()

def exercise_slot_boundaries(database: Path) -> SlotBoundaryOutcome:
    connection, store, _ = configured_executor(database)
    try:
        connection.execute(
            "UPDATE idempotency_cipher_key_versions "
            "SET reserved_encryption_slots = ? WHERE version_label = ?",
            ((2**23) - 1, "primary"),
        )
        connection.commit()
        store.reserve_nonce(invocation(), now_epoch=100)
        soft_epoch = store.key_version_state("primary").soft_limit_reported_epoch
        connection.execute(
            "UPDATE idempotency_cipher_key_versions "
            "SET reserved_encryption_slots = ? WHERE version_label = ?",
            (2**24, "primary"),
        )
        connection.commit()
        try:
            store.reserve_nonce(invocation(), now_epoch=101)
        except RuntimeError:
            hard_limit_raised = True
        else:
            hard_limit_raised = False
        return SlotBoundaryOutcome(soft_epoch, hard_limit_raised)
    finally:
        connection.close()

def exercise_gc(database: Path) -> GcOutcome:
    connection, store, _ = configured_executor(database)
    try:
        for index in range(101):
            _seed_completed_result(
                connection,
                store,
                CompletedResultSeed(outcome(), 0),
                request=invocation(key_hash=index.to_bytes(32, "big")),
            )
        deleted = store.gc_expired_results(limit=100)
        return GcOutcome(deleted, count_rows(connection, "idempotency_results"))
    finally:
        connection.close()

def exercise_nonce_ledger_gc(database: Path) -> int:
    connection, store, _ = configured_executor(database)
    try:
        _seed_completed_result(connection, store)
        connection.execute("DELETE FROM idempotency_results")
        connection.commit()
        return count_rows(connection, "idempotency_cipher_nonces")
    finally:
        connection.close()
