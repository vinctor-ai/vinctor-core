from __future__ import annotations

import base64
from dataclasses import replace
from typing import Literal

import pytest
from idempotency_postgres_fixtures import (
    configured_postgres_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_postgres_phase01_probe import MutationProbe
from idempotency_postgres_phase01_results import (
    CompletedResultSeed,
    phase_zero_counts,
    seed_completed_result,
)

from vinctor_service.idempotency_keyring import load_idempotency_keyring
from vinctor_service.idempotency_models import (
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_postgres import (
    PostgresIdempotencyStore,
    PostgresIdempotentMutationExecutor,
)
from vinctor_service.postgres import connect_postgres


def test_postgres_gc_preserves_expiry_tamper_and_fails_closed(
    requires_postgres: str,
) -> None:
    # Given an authentic completed row whose authenticated expiry is tampered into the past.
    connection, store, _executor = configured_postgres_executor(requires_postgres)
    try:
        request = invocation()
        now_epoch = store.database_epoch()
        seed_completed_result(
            connection,
            store,
            CompletedResultSeed(
                request,
                outcome().response,
                now_epoch,
                now_epoch + request.max_terminal_ttl_seconds,
            ),
        )
        with connection.transaction():
            connection.execute(
                "UPDATE idempotency_results SET created_at_epoch = 0, expires_at_epoch = 1"
            )

        # When bounded GC considers the row.
        with pytest.raises(IdempotencyResultUnavailable):
            store.gc_expired_results(limit=100)

        # Then the unauthenticated candidate is preserved.
        assert count_rows(connection, "idempotency_results") == 1
    finally:
        connection.close()

def test_postgres_expired_result_rejects_unsafe_historical_key_removal(
    requires_postgres: str,
) -> None:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    new = base64.b64encode(b"n" * 32).decode("ascii")
    old_active = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"old":"{old}","new":"{new}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "old",
        }
    )
    new_only = load_idempotency_keyring(
        {
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": f'{{"new":"{new}"}}',
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "new",
        }
    )
    connection = connect_postgres(requires_postgres)
    old_store = PostgresIdempotencyStore(connection, keyring=old_active)
    request = invocation()
    seed_completed_result(
        connection,
        old_store,
        CompletedResultSeed(
            request,
            outcome().response,
            0,
            1,
        ),
    )
    store = PostgresIdempotencyStore(connection, keyring=new_only)
    executor = PostgresIdempotentMutationExecutor(store)
    probe = MutationProbe()

    try:
        with pytest.raises(IdempotencyResultUnavailable):
            executor.execute(request, probe)
        assert (
            probe.calls,
            phase_zero_counts(connection).results,
            count_rows(connection, "idempotency_cipher_nonces"),
        ) == (0, 1, 1)
    finally:
        connection.close()

@pytest.mark.parametrize("condition", ("malformed", "disabled"))
def test_postgres_phase_zero_fails_closed_before_reservation(
    requires_postgres: str,
    condition: Literal["malformed", "disabled"],
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    probe = MutationProbe()
    try:
        request = invocation()
        if condition == "malformed":
            request = replace(request, key_hash=b"x" * 31)
        else:
            now_epoch = store.database_epoch()
            connection.execute(
                "UPDATE idempotency_cipher_key_versions "
                "SET write_disabled_epoch = %s, write_disabled_reason = 'rotation' "
                "WHERE version_label = 'primary'",
                (now_epoch,),
            )
            connection.commit()
        before = phase_zero_counts(connection)

        with pytest.raises(IdempotencyWriteUnavailable):
            executor.execute(request, probe)

        assert phase_zero_counts(connection) == before
        assert before.nonces == before.results == before.audits == 0
        assert probe.calls == 0
    finally:
        connection.close()

@pytest.mark.parametrize(
    "method",
    ("database_epoch", "lookup", "key_version_state"),
)
def test_postgres_phase_zero_read_rejects_outer_transaction_without_ending_it(
    requires_postgres: str,
    method: Literal["database_epoch", "lookup", "key_version_state"],
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    observer = connect_postgres(requires_postgres)
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS idempotency_phase01_outer_marker(value TEXT PRIMARY KEY)"
        )
        connection.commit()
        connection.execute("INSERT INTO idempotency_phase01_outer_marker(value) VALUES ('caller')")

        with pytest.raises(IdempotencyResultUnavailable):
            if method == "database_epoch":
                store.database_epoch()
            elif method == "lookup":
                store.lookup(invocation(), now_epoch=0)
            else:
                store.key_version_state("primary")

        assert int(connection.info.transaction_status) == 2
        connection.rollback()
        row = observer.execute("SELECT COUNT(*) FROM idempotency_phase01_outer_marker").fetchone()
        assert row is not None and int(row[0]) == 0
    finally:
        connection.rollback()
        observer.close()
        connection.close()
