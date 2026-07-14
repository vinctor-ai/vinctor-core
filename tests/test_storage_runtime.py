from __future__ import annotations

from contextlib import nullcontext
from pathlib import Path

import pytest

from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.storage_runtime import prepare_decision_storage


def test_prepare_decision_storage_selects_sqlite_and_reports_ready(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"

    handle = prepare_decision_storage(
        ServiceRuntimeConfig(sqlite_db_path=db_path, storage_backend="sqlite")
    )
    try:
        assert handle.backend == "sqlite"
        assert isinstance(handle.service, SQLiteV1Service)
        assert handle.is_ready()
        assert db_path.exists()
    finally:
        handle.close()


def test_prepare_decision_storage_selects_postgres(monkeypatch) -> None:
    calls: list[str] = []

    class FakeCursor:
        def fetchone(self):
            return (1,)

    class FakeConnection:
        closed = False

        def execute(self, query: str):
            calls.append(query)
            return FakeCursor()

        def transaction(self):
            return nullcontext()

        def close(self):
            self.closed = True

    connection = FakeConnection()
    service = object()
    monkeypatch.setattr(
        "vinctor_service.storage_runtime.connect_postgres",
        lambda dsn: calls.append(dsn) or connection,
    )
    monkeypatch.setattr(
        "vinctor_service.storage_runtime.PostgresV1Service",
        lambda conn: service,
    )

    handle = prepare_decision_storage(
        ServiceRuntimeConfig(
            storage_backend="postgres",
            postgres_dsn="postgresql://vinctor@db/vinctor",
        )
    )
    try:
        assert handle.backend == "postgres"
        assert handle.service is service
        assert handle.is_ready()
        assert calls == [
            "postgresql://vinctor@db/vinctor",
            "SELECT 1",
            "SELECT 1",
        ]
    finally:
        handle.close()
    assert connection.closed


def test_prepare_decision_storage_closes_connection_on_initialization_error(
    monkeypatch,
) -> None:
    class FakeConnection:
        closed = False

        def close(self):
            self.closed = True

    connection = FakeConnection()
    monkeypatch.setattr(
        "vinctor_service.storage_runtime.connect_postgres",
        lambda _dsn: connection,
    )

    def fail(_conn):
        raise RuntimeError("schema unavailable")

    monkeypatch.setattr("vinctor_service.storage_runtime.PostgresV1Service", fail)

    with pytest.raises(RuntimeError, match="schema unavailable"):
        prepare_decision_storage(
            ServiceRuntimeConfig(
                storage_backend="postgres",
                postgres_dsn="postgresql://vinctor@db/vinctor",
            )
        )

    assert connection.closed
