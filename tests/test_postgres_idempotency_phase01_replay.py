from __future__ import annotations

from dataclasses import replace

import pytest
from idempotency_postgres_fixtures import (
    configured_postgres_executor,
    invocation,
    outcome,
)
from idempotency_postgres_phase01_probe import MutationProbe
from idempotency_postgres_phase01_results import (
    CompletedResultFault,
    CompletedResultSeed,
    phase_zero_counts,
    seed_completed_result,
    tamper_completed_result,
)

from vinctor_service.idempotency_models import (
    IdempotencyConflict,
    IdempotencyResultUnavailable,
)


def test_postgres_phase_zero_replays_exact_body_and_observation(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    probe = MutationProbe()
    try:
        request = invocation()
        terminal = outcome(
            b'{"secret":"exact"}',
            error_code="forbidden",
            decision="deny",
        ).response
        now_epoch = store.database_epoch()
        seed_completed_result(
            connection,
            store,
            CompletedResultSeed(
                request,
                terminal,
                now_epoch,
                now_epoch + request.max_terminal_ttl_seconds,
            ),
        )
        before = phase_zero_counts(connection)

        assert executor.execute(request, probe) == terminal

        assert phase_zero_counts(connection) == before
        assert probe.calls == 0
    finally:
        connection.close()

def test_postgres_phase_zero_conflict_does_not_mutate_state(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    probe = MutationProbe()
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
        before = phase_zero_counts(connection)

        with pytest.raises(IdempotencyConflict) as captured:
            executor.execute(invocation(fingerprint=b"x" * 32), probe)

        assert str(captured.value) == "idempotency key conflict"
        assert phase_zero_counts(connection) == before
        assert probe.calls == 0
    finally:
        connection.close()

def test_postgres_phase_zero_scopes_same_key_hash_by_authority(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    probe = MutationProbe()
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
        before = phase_zero_counts(connection)
        other_authority = replace(request, principal="agent:b")

        assert executor.execute(other_authority, probe) == outcome().response

        after = phase_zero_counts(connection)
        assert after.nonces == before.nonces + 1
        assert after.results == before.results + 1
        assert after.audits == before.audits == 0
        assert probe.calls == 1
    finally:
        connection.close()

@pytest.mark.parametrize(
    "fault",
    ("corrupt", "expiry_metadata", "fingerprint_metadata", "unknown_key"),
)
def test_postgres_phase_zero_authenticates_before_classification(
    requires_postgres: str,
    fault: CompletedResultFault,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    probe = MutationProbe()
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
        tamper_completed_result(connection, fault)
        before = phase_zero_counts(connection)

        with pytest.raises(IdempotencyResultUnavailable) as captured:
            executor.execute(request, probe)

        assert str(captured.value) == "idempotency unavailable"
        assert phase_zero_counts(connection) == before
        assert before.results == before.nonces == 1
        assert before.audits == 0
        assert probe.calls == 0
    finally:
        connection.close()

def test_postgres_phase_zero_authentic_expiry_precedes_conflict(
    requires_postgres: str,
) -> None:
    connection, store, executor = configured_postgres_executor(requires_postgres)
    probe = MutationProbe()
    try:
        request = invocation()
        now_epoch = store.database_epoch()
        seed_completed_result(
            connection,
            store,
            CompletedResultSeed(
                request,
                outcome().response,
                now_epoch - 100,
                now_epoch - 1,
            ),
        )
        before = phase_zero_counts(connection)

        assert executor.execute(
            replace(request, request_fingerprint=b"x" * 32),
            probe,
        ) == outcome().response

        after = phase_zero_counts(connection)
        assert after.nonces == before.nonces + 1
        assert after.results == before.results == 1
        assert after.audits == before.audits == 0
        assert probe.calls == 1
    finally:
        connection.close()
