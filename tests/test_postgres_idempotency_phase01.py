from __future__ import annotations

from typing import Literal, assert_never

import pytest
from idempotency_postgres_fixtures import invocation
from idempotency_postgres_phase01_fake import StatefulPostgresConnection
from psycopg import Error as PostgresError

from vinctor_service.idempotency_models import IdempotencyResultUnavailable
from vinctor_service.idempotency_postgres import PostgresIdempotencyStore
from vinctor_service.postgres_connection import SerializedPostgresConnection

PhaseZeroRead = Literal["database_epoch", "key_version_state", "lookup"]


def _invoke_phase_zero_read(
    store: PostgresIdempotencyStore,
    operation: PhaseZeroRead,
) -> None:
    match operation:
        case "database_epoch":
            store.database_epoch()
        case "key_version_state":
            store.key_version_state("primary")
        case "lookup":
            store.lookup(invocation(), now_epoch=123)
        case unreachable:
            assert_never(unreachable)


@pytest.mark.parametrize(
    "operation",
    ("database_epoch", "key_version_state", "lookup"),
)
def test_postgres_phase_zero_rejects_non_idle_before_any_boundary_or_sql(
    operation: PhaseZeroRead,
) -> None:
    # Given an unrelated caller-owned implicit transaction on the shared connection.
    raw = StatefulPostgresConnection(transaction_status=2)
    store = PostgresIdempotencyStore(
        SerializedPostgresConnection(raw),
        keyring=None,
    )

    # When any public Phase 0 read is invoked.
    try:
        _invoke_phase_zero_read(store, operation)
    except IdempotencyResultUnavailable:
        rejected = True
    else:
        rejected = False

    # Then it rejects before SQL and preserves the caller's exact transaction boundary.
    assert (
        rejected,
        len(raw.executed_sql),
        raw.commits,
        raw.rollbacks,
        raw.info.transaction_status,
    ) == (True, 0, 0, 0, 2)


@pytest.mark.parametrize(
    "operation",
    ("database_epoch", "key_version_state", "lookup"),
)
def test_postgres_phase_zero_idle_read_closes_only_its_own_transaction(
    operation: PhaseZeroRead,
) -> None:
    # Given an idle connection on which the Phase 0 read will own any implicit transaction.
    raw = StatefulPostgresConnection(transaction_status=0)
    store = PostgresIdempotencyStore(
        SerializedPostgresConnection(raw),
        keyring=None,
    )

    # When the read completes normally.
    _invoke_phase_zero_read(store, operation)

    # Then only its self-started read transaction is committed to IDLE.
    assert (
        len(raw.executed_sql),
        raw.commits,
        raw.rollbacks,
        raw.info.transaction_status,
    ) == (1, 1, 0, 0)


@pytest.mark.parametrize(
    "operation",
    ("database_epoch", "key_version_state", "lookup"),
)
def test_postgres_phase_zero_failed_owned_read_rolls_back_and_is_coarse(
    operation: PhaseZeroRead,
) -> None:
    # Given an idle connection whose first Phase 0 SQL fails after opening a transaction.
    raw = StatefulPostgresConnection(transaction_status=0, fail_execute=True)
    store = PostgresIdempotencyStore(
        SerializedPostgresConnection(raw),
        keyring=None,
    )

    # When the read encounters the PostgreSQL failure.
    try:
        _invoke_phase_zero_read(store, operation)
    except IdempotencyResultUnavailable:
        coarse_error = True
    except PostgresError:
        coarse_error = False
    else:
        coarse_error = False

    # Then it rolls back only that owned transaction and returns the public coarse error.
    assert (
        coarse_error,
        len(raw.executed_sql),
        raw.commits,
        raw.rollbacks,
        raw.info.transaction_status,
    ) == (True, 1, 0, 1, 0)
