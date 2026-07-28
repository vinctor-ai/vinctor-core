from __future__ import annotations

import pytest
from idempotency_postgres_faults import inject_commit_ack_loss
from idempotency_postgres_fixtures import (
    configured_postgres_executor,
    count_rows,
    invocation,
    outcome,
)

from vinctor_service.postgres import (
    connect_postgres,
)


def test_postgres_reservation_commit_ack_loss_quarantines_connection_before_callback(
    requires_postgres: str,
) -> None:
    connection, _, executor = configured_postgres_executor(requires_postgres)
    inject_commit_ack_loss(
        connection,
        transaction_boundary=3,
        commit_happened=True,
    )
    calls = 0

    def mutation():
        nonlocal calls
        calls += 1
        return outcome()

    with pytest.raises(RuntimeError):
        executor.execute(invocation(), mutation)
    assert calls == 0
    assert connection.is_quarantined is True
    observer = connect_postgres(requires_postgres)
    try:
        assert count_rows(observer, "idempotency_cipher_nonces") == 1
    finally:
        observer.close()

def test_postgres_business_commit_ack_loss_recovers_only_via_fresh_primary_lookup(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    generation = connection.generation
    inject_commit_ack_loss(
        connection,
        transaction_boundary=6,
        commit_happened=True,
    )
    with pytest.raises(RuntimeError):
        executor.execute(invocation(), lambda: outcome())
    replay = executor.execute(invocation(), lambda: pytest.fail("replay re-entered callback"))
    assert replay.body == b'{"ok":true}'
    assert connection.generation > generation

def test_postgres_unknown_commit_happened_replays_and_did_not_run_callback_twice(
    requires_postgres: str,
) -> None:
    connection, _, executor = configured_postgres_executor(requires_postgres)
    inject_commit_ack_loss(
        connection,
        transaction_boundary=6,
        commit_happened=True,
    )
    calls = 0

    def mutation():
        nonlocal calls
        calls += 1
        return outcome()

    with pytest.raises(RuntimeError):
        executor.execute(invocation(), mutation)
    assert executor.execute(invocation(), mutation).body == b'{"ok":true}'
    assert calls == 1

def test_postgres_unknown_commit_not_happened_allows_fresh_reservation(
    requires_postgres: str,
) -> None:
    connection, _, executor = configured_postgres_executor(requires_postgres)
    inject_commit_ack_loss(
        connection,
        transaction_boundary=6,
        commit_happened=False,
    )
    with pytest.raises(RuntimeError):
        executor.execute(invocation(), lambda: outcome())
    assert executor.execute(invocation(), lambda: outcome()).status_code == 201

def test_postgres_quarantine_swaps_physical_generation_without_rebuilding_service_graph(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    generation = connection.generation
    connection.quarantine_after_ambiguous_commit(generation)
    assert connection.execute("SELECT 1").fetchone() == (1,)
    assert connection.generation > generation
    assert executor.store is store

def test_postgres_readiness_is_false_until_fresh_generation_passes_all_checks(
    requires_postgres: str,
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    connection.quarantine_after_ambiguous_commit(connection.generation)
    assert store.readiness() is False
    assert connection.execute("SELECT 1").fetchone() == (1,)
    connection.rollback()
    assert store.readiness() is True

def test_postgres_barrier_ambiguity_may_recover_but_business_callback_may_not(
    requires_postgres: str,
) -> None:
    connection, store, _ = configured_postgres_executor(requires_postgres)
    inject_commit_ack_loss(
        connection,
        transaction_boundary=2,
        commit_happened=True,
    )
    store.write_disable(version="primary", reason="rotation")
    observer = connect_postgres(requires_postgres)
    try:
        state = observer.execute(
            "SELECT write_disabled_epoch FROM idempotency_cipher_key_versions "
            "WHERE version_label = %s",
            ("primary",),
        ).fetchone()
        assert state is not None
        assert state[0] is not None
        assert count_rows(observer, "idempotency_results") == 0
    finally:
        observer.close()
