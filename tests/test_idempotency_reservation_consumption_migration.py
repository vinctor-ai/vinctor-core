from __future__ import annotations

from pathlib import Path

from idempotency_postgres_fixtures import configured_postgres_executor
from idempotency_postgres_fixtures import invocation as postgres_invocation
from idempotency_postgres_fixtures import outcome as postgres_outcome
from idempotency_sqlite_fixtures import configured_executor
from idempotency_sqlite_fixtures import invocation as sqlite_invocation
from idempotency_sqlite_fixtures import outcome as sqlite_outcome

from vinctor_service.postgres import init_postgres_schema
from vinctor_service.sqlite import init_sqlite_schema


def test_sqlite_pre_release_schema_adds_and_backfills_claimed_marker(
    tmp_path: Path,
) -> None:
    connection, store, _executor = configured_executor(tmp_path / "migration.sqlite")
    owner = sqlite_invocation()
    reserved = store.reserve_nonce(owner, now_epoch=100)
    try:
        store.complete(owner, reserved, sqlite_outcome)
        connection.execute("ALTER TABLE idempotency_cipher_nonces DROP COLUMN claimed_at_epoch")
        connection.commit()

        init_sqlite_schema(connection)

        columns = {
            str(row[1])
            for row in connection.execute("PRAGMA table_info(idempotency_cipher_nonces)").fetchall()
        }
        consumed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = ? AND nonce = ?",
            (reserved.version, reserved.nonce),
        ).fetchone()
        assert "claimed_at_epoch" in columns
        assert consumed is not None
        assert consumed[0] is not None
        assert int(consumed[0]) >= reserved.reserved_at_epoch
    finally:
        connection.close()


def test_postgres_pre_release_schema_adds_and_backfills_claimed_marker(
    requires_postgres: str,
) -> None:
    connection, store, _executor = configured_postgres_executor(requires_postgres)
    owner = postgres_invocation()
    reserved = store.reserve_nonce(owner, now_epoch=store.database_epoch())
    try:
        store.complete(owner, reserved, postgres_outcome)
        with connection.transaction():
            connection.execute("ALTER TABLE idempotency_cipher_nonces DROP COLUMN claimed_at_epoch")

        init_postgres_schema(connection)

        consumed = connection.execute(
            "SELECT claimed_at_epoch FROM idempotency_cipher_nonces "
            "WHERE cipher_key_version = %s AND nonce = %s",
            (reserved.version, reserved.nonce),
        ).fetchone()
        connection.commit()
        assert consumed is not None
        assert consumed[0] is not None
        assert int(consumed[0]) >= reserved.reserved_at_epoch
    finally:
        init_postgres_schema(connection)
        connection.close()
