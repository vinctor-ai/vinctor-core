from __future__ import annotations

from contextlib import AbstractContextManager
from types import TracebackType
from typing import Any

import pytest

from vinctor_service.postgres_connection import SerializedPostgresConnection
from vinctor_service.service_config import ServiceRuntimeConfig


class _Cursor:
    def fetchone(self) -> tuple[int]:
        return (1,)


class _Transaction(AbstractContextManager[None]):
    def __enter__(self) -> None:
        return None

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        return False


class _Info:
    transaction_status = 0


class _PhysicalConnection:
    def __init__(self, name: str, *, active_write_disabled: bool = False) -> None:
        self.name = name
        self.active_write_disabled = active_write_disabled
        self.closed = False
        self.broken = False
        self.info = _Info()

    def execute(self, _statement: str, *_args: Any, **_kwargs: Any) -> _Cursor:
        return _Cursor()

    def transaction(self) -> _Transaction:
        return _Transaction()

    def close(self) -> None:
        self.closed = True


class _Service:
    def close(self) -> None:
        return None


def test_service_builder_active_disabled_recovery_is_compatibility_only_and_one_shot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from vinctor_service import service_runtime

    primary = _PhysicalConnection("primary")
    candidate = _PhysicalConnection("candidate", active_write_disabled=True)
    reconnects = 0
    compatibility_checks: list[str] = []
    readiness_checks: list[str] = []

    def reconnect() -> _PhysicalConnection:
        nonlocal reconnects
        reconnects += 1
        return candidate

    def compatible(connection: _PhysicalConnection, *, keyring: object) -> None:
        del keyring
        compatibility_checks.append(connection.name)

    def operationally_ready(
        connection: _PhysicalConnection,
        *,
        keyring: object,
    ) -> None:
        del keyring
        readiness_checks.append(connection.name)
        if connection.active_write_disabled:
            raise RuntimeError("active version is write-disabled")

    connection = SerializedPostgresConnection(primary, reconnect=reconnect)
    monkeypatch.setattr(service_runtime, "connect_postgres", lambda _dsn: connection)
    monkeypatch.setattr(service_runtime, "PostgresV1Service", lambda _conn: _Service())
    monkeypatch.setattr(service_runtime, "PostgresLocalKeyRepository", lambda _conn: object())
    monkeypatch.setattr(
        service_runtime,
        "create_v1_http_server",
        lambda *_args, **_kwargs: _Server(),
    )
    monkeypatch.setattr(service_runtime, "require_postgres_idempotency_compatible", compatible)
    monkeypatch.setattr(service_runtime, "require_postgres_idempotency_ready", operationally_ready)
    handle = service_runtime.prepare_service_runtime(
        ServiceRuntimeConfig(
            storage_backend="postgres",
            postgres_dsn="postgresql://vinctor@db/vinctor",
            port=0,
        )
    )
    generation = connection.generation
    assert connection.quarantine_after_ambiguous_commit(generation) is True
    body_entered = False
    try:
        with connection.fresh_authoritative_recovery(after_generation=generation) as authority:
            body_entered = True
            assert authority is candidate
            assert authority.execute("SELECT durable barrier").fetchone() == (1,)
        assert body_entered is True
        assert compatibility_checks == ["candidate"]
        assert readiness_checks == []
        assert reconnects == 1
        assert candidate.closed is True
        assert connection.is_quarantined is True
        assert connection.is_ready is False
    finally:
        handle.close()


class _Server:
    server_address = ("127.0.0.1", 0)

    def server_close(self) -> None:
        return None
