from __future__ import annotations

import inspect

import pytest
from idempotency_postgres_fixtures import (
    schema_versions,
)
from idempotency_postgres_schema_contract import (
    assert_postgres_constraints,
    postgres_idempotency_schema_shape,
)
from idempotency_schema_bootstrap_scenarios import (
    BootstrapConflict,
    exercise_postgres_bootstrap_conflict,
    exercise_postgres_bootstrap_convergence,
)
from idempotency_schema_contracts import assert_schema_shape

from vinctor_service.postgres import (
    connect_postgres,
    init_postgres_schema,
)


def test_postgres_keyring_registration_floors_epoch_before_bigint_cast() -> None:
    from vinctor_service import postgres

    source = inspect.getsource(postgres._register_postgres_idempotency_keyring)

    assert "FLOOR(EXTRACT(EPOCH FROM transaction_timestamp()))::BIGINT" in source


def test_postgres_migration_8_has_exact_tables_constraints_index_and_foreign_keys(
    requires_postgres: str,
) -> None:
    connection = connect_postgres(requires_postgres)
    try:
        init_postgres_schema(connection)
        first_shape = postgres_idempotency_schema_shape(connection)
        connection.commit()
        init_postgres_schema(connection)
        second_shape = postgres_idempotency_schema_shape(connection)
        versions = schema_versions(connection)
        connection.commit()
        assert versions == tuple(range(1, 9))
        assert first_shape == second_shape
        assert_schema_shape(first_shape)
        assert_postgres_constraints(connection)
    finally:
        connection.close()

def test_postgres_keyring_bootstrap_converges_across_connections(
    requires_postgres: str,
) -> None:
    # Given two PostgreSQL startups with the same configured label and commitment.
    # When they register concurrently against one migrated database.
    result = exercise_postgres_bootstrap_convergence(requires_postgres)
    # Then one immutable zero-reservation registry row remains.
    assert result.registrations == (("primary", 0),)

@pytest.mark.parametrize("conflict", ("label", "commitment"))
def test_postgres_keyring_bootstrap_conflict_is_atomic_and_redacted(
    requires_postgres: str,
    conflict: BootstrapConflict,
) -> None:
    # Given an existing immutable registry row and one conflicting two-key startup.
    # When the new startup attempts to register both configured versions.
    result = exercise_postgres_bootstrap_conflict(requires_postgres, conflict)
    # Then it fails coarsely and rolls back the otherwise valid new row.
    assert result.error == "invalid idempotency key configuration"
    assert result.registrations == ("primary",)
    assert result.secret_redacted is True

def test_postgres_signed_advisory_key_is_stable_and_domain_separated() -> None:
    from vinctor_service.idempotency_postgres import signed_advisory_key

    first = signed_advisory_key("ws", "agent:a", "grant.issue.v1", b"k" * 32)
    second = signed_advisory_key("ws", "agent:a", "grant.issue.v1", b"k" * 32)
    other = signed_advisory_key("ws", "agent:a", "subject_token.mint.v1", b"k" * 32)
    assert first == second
    assert first != other
    assert -(2**63) <= first < 2**63

def test_postgres_7_upgrades_to_8_and_repeated_8_start_is_idempotent(
    requires_postgres: str,
) -> None:
    connection = connect_postgres(requires_postgres)
    with connection.transaction():
        connection.execute("DROP TABLE IF EXISTS idempotency_results")
        connection.execute("DROP TABLE IF EXISTS idempotency_cipher_nonces")
        connection.execute("DROP TABLE IF EXISTS idempotency_cipher_key_versions")
        connection.execute("DELETE FROM schema_migrations WHERE version = 8")
    assert schema_versions(connection) == tuple(range(1, 8))
    connection.commit()
    init_postgres_schema(connection)
    first = schema_versions(connection)
    first_shape = postgres_idempotency_schema_shape(connection)
    connection.commit()
    init_postgres_schema(connection)
    second = schema_versions(connection)
    second_shape = postgres_idempotency_schema_shape(connection)
    connection.close()
    assert first == second == tuple(range(1, 9))
    assert first_shape == second_shape
    assert_schema_shape(first_shape)
