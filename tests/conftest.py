from __future__ import annotations

import os

import pytest

from vinctor_service.postgres import connect_postgres, init_postgres_schema

_POSTGRES_DSN = os.environ.get("VINCTOR_TEST_POSTGRES_DSN")


def _quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _clean_postgres_database(dsn: str) -> None:
    conn = connect_postgres(dsn)
    try:
        init_postgres_schema(conn)
        with conn.transaction():
            rows = conn.execute(
                "SELECT table_name "
                "FROM information_schema.tables "
                "WHERE table_schema = current_schema() "
                "AND table_type = 'BASE TABLE' "
                "AND table_name <> 'schema_migrations' "
                "ORDER BY table_name"
            ).fetchall()
            tables = tuple(str(row[0]) for row in rows)
            if tables:
                quoted_tables = ", ".join(_quote_identifier(table) for table in tables)
                conn.execute(f"TRUNCATE TABLE {quoted_tables}")
    finally:
        conn.close()


@pytest.fixture
def requires_postgres() -> str:
    if _POSTGRES_DSN is None:
        pytest.skip("VINCTOR_TEST_POSTGRES_DSN is not set")
    return _POSTGRES_DSN


@pytest.fixture(autouse=True)
def clean_postgres_database(request: pytest.FixtureRequest) -> None:
    if "requires_postgres" not in request.fixturenames:
        return
    _clean_postgres_database(request.getfixturevalue("requires_postgres"))
