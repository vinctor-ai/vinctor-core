from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from idempotency_schema_bootstrap_scenarios import (
    BootstrapConflict,
    exercise_sqlite_absent_keyring_with_unexpired_result,
    exercise_sqlite_bootstrap_conflict,
    exercise_sqlite_bootstrap_convergence,
)
from idempotency_schema_contracts import assert_schema_shape
from idempotency_sqlite_schema_contract import (
    assert_sqlite_constraints,
    sqlite_idempotency_schema_shape,
)

from vinctor_service.sqlite import get_sqlite_schema_versions, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite

if TYPE_CHECKING:
    pass

def test_sqlite_migration_18_has_exact_tables_constraints_index_and_foreign_keys() -> None:
    # Given a fresh database at the production serialized SQLite connection seam.
    connection = connect_sqlite(":memory:")
    try:
        # When migration 18 is applied twice.
        init_sqlite_schema(connection)
        first_shape = sqlite_idempotency_schema_shape(connection)
        init_sqlite_schema(connection)
        second_shape = sqlite_idempotency_schema_shape(connection)
        versions = get_sqlite_schema_versions(connection)
        # Then the exact shape is stable and every declared constraint rejects bad data.
        assert versions == tuple(range(1, 19))
        assert first_shape == second_shape
        assert_schema_shape(first_shape)
        assert_sqlite_constraints(connection)
    finally:
        connection.close()

def test_sqlite_keyring_bootstrap_converges_across_connections(tmp_path: Path) -> None:
    # Given two SQLite startups with the same configured label and commitment.
    # When they register concurrently against one migrated database.
    result = exercise_sqlite_bootstrap_convergence(tmp_path / "bootstrap.sqlite3")
    # Then one immutable zero-reservation registry row remains.
    assert result.registrations == (("primary", 0),)

@pytest.mark.parametrize("conflict", ("label", "commitment"))
def test_sqlite_keyring_bootstrap_conflict_is_atomic_and_redacted(
    tmp_path: Path,
    conflict: BootstrapConflict,
) -> None:
    # Given an existing immutable registry row and one conflicting two-key startup.
    # When the new startup attempts to register both configured versions.
    result = exercise_sqlite_bootstrap_conflict(
        tmp_path / f"conflict-{conflict}.sqlite3",
        conflict,
    )
    # Then it fails coarsely and rolls back the otherwise valid new row.
    assert result.error == "invalid idempotency key configuration"
    assert result.registrations == ("primary",)
    assert result.secret_redacted is True

def test_sqlite_absent_keyring_rejects_unexpired_ciphertext(tmp_path: Path) -> None:
    # Given one unexpired encrypted result registered under a configured version.
    # When a fully absent-keyring service starts against the authoritative schema.
    error = exercise_sqlite_absent_keyring_with_unexpired_result(tmp_path / "unexpired.sqlite3")
    # Then startup fails closed before any mutation service is exposed.
    assert error == "invalid idempotency key configuration"

def test_sqlite_17_upgrades_to_18_and_old_binary_gate_rejects_18(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "upgrade.sqlite3"
    connection = connect_sqlite(database)
    connection.execute(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
    )
    for version in range(1, 18):
        connection.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (version, "legacy-fixture"),
        )
    connection.commit()
    init_sqlite_schema(connection)
    first_shape = sqlite_idempotency_schema_shape(connection)
    init_sqlite_schema(connection)
    second_shape = sqlite_idempotency_schema_shape(connection)
    assert get_sqlite_schema_versions(connection) == tuple(range(1, 19))
    assert first_shape == second_shape
    assert_schema_shape(first_shape)
    import vinctor_service.sqlite as sqlite_module
    from vinctor_service.sqlite import SQLiteV1Service

    monkeypatch.setattr(sqlite_module, "SQLITE_SCHEMA_VERSION_MAX", 17)
    with pytest.raises(RuntimeError):
        SQLiteV1Service(connection, initialize_schema=False)
    connection.close()
