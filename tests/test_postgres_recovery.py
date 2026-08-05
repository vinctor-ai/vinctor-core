from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from http.client import HTTPConnection
from threading import Event, Thread
from types import TracebackType
from typing import Any

import pytest

from vinctor_service.idempotency_models import AmbiguousCommitError
from vinctor_service.postgres import connect_postgres
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import ServiceRuntimeHandle, prepare_service_runtime


class _FakeOperationalError(RuntimeError):
    pass


class _FakeCursor:
    def __init__(self, row: tuple[Any, ...]) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...]:
        return self._row


class _FakeInfo:
    def __init__(self, connection: _FakePgConnection) -> None:
        self._connection = connection

    @property
    def transaction_status(self) -> int:
        return 0 if self._connection.transaction_depth == 0 else 2


class _FakeTransaction:
    def __init__(self, connection: _FakePgConnection) -> None:
        self._connection = connection

    def __enter__(self) -> _FakeTransaction:
        if self._connection.broken:
            raise _FakeOperationalError("server closed the connection")
        self._connection.transaction_depth += 1
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self._connection.transaction_depth -= 1
        if exc is None and self._connection.fail_commit:
            self._connection.fail_commit = False
            self._connection.broken = True
            raise _FakeOperationalError("commit outcome is unknown")
        return False


class _FakePgConnection:
    def __init__(
        self,
        name: str,
        *,
        fail_first_execute: bool = False,
        fail_commit: bool = False,
    ) -> None:
        self.name = name
        self.fail_first_execute = fail_first_execute
        self.fail_commit = fail_commit
        self.statements: list[str] = []
        self.transaction_depth = 0
        self.closed = False
        self.broken = False
        self.info = _FakeInfo(self)

    def transaction(self) -> _FakeTransaction:
        return _FakeTransaction(self)

    def execute(self, statement: str) -> _FakeCursor:
        if self.broken:
            raise _FakeOperationalError("server closed the connection")
        self.statements.append(statement)
        if self.fail_first_execute:
            self.fail_first_execute = False
            self.broken = True
            raise _FakeOperationalError("server closed the connection")
        return _FakeCursor((1,))

    def close(self) -> None:
        self.closed = True


class _FakeLibpq:
    @staticmethod
    def version() -> int:
        return 170000


class _FakeCapabilities:
    """What `connect_postgres` asks before it dials.

    The Postgres backend refuses to start without a bounded
    Connection.cancel_safe() (PKA-146), so a stand-in for psycopg has to answer
    the capability question the way the real module does.
    """

    @staticmethod
    def has_cancel_safe(check: bool = False) -> bool:
        return True


class _FakePsycopg:
    Error = _FakeOperationalError
    OperationalError = _FakeOperationalError
    pq = _FakeLibpq()
    capabilities = _FakeCapabilities()
    __version__ = "3.2.0"

    def __init__(
        self,
        connections: list[_FakePgConnection],
        *,
        recovery_failures: int = 0,
        recovery_gate: tuple[Event, Event] | None = None,
    ) -> None:
        self._connections = connections
        self._recovery_failures = recovery_failures
        self._recovery_gate = recovery_gate
        self.connect_calls = 0

    def connect(self, dsn: str) -> _FakePgConnection:
        self.connect_calls += 1
        if self.connect_calls > 1 and self._recovery_failures > 0:
            self._recovery_failures -= 1
            raise _FakeOperationalError("database unavailable")
        if self.connect_calls > 1 and self._recovery_gate is not None:
            entered, release = self._recovery_gate
            entered.set()
            assert release.wait(timeout=5)
        return self._connections.pop(0)


def test_postgres_connection_recovers_on_next_scope_without_replaying_failed_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a write whose commit acknowledgement is lost with the PostgreSQL backend.
    failed = _FakePgConnection("failed", fail_commit=True)
    replacement = _FakePgConnection("replacement")
    driver = _FakePsycopg([failed, replacement])
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    connection = connect_postgres("postgresql://vinctor:secret@db/vinctor")
    emissions: list[str] = []

    # When the write fails and a later, independent transaction starts.
    with pytest.raises(AmbiguousCommitError), connection.transaction():
        connection.emit_or_defer(lambda: emissions.append("failed"))
        connection.execute("INSERT INTO durable_state VALUES (1)")
    with connection.transaction():
        connection.emit_or_defer(lambda: emissions.append("replacement"))
        row = connection.execute("SELECT 1").fetchone()

    # Then only the later operation uses the replacement; the write is not replayed.
    assert row == (1,)
    assert failed.statements == ["INSERT INTO durable_state VALUES (1)"]
    assert replacement.statements[0] == replacement.statements[-1] == "SELECT 1"
    assert any("schema_migrations" in statement for statement in replacement.statements)
    assert driver.connect_calls == 2
    assert emissions == ["replacement"]


def test_postgres_reconnect_attempts_and_backoff_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a poisoned connection and a PostgreSQL endpoint that stays unavailable.
    failed = _FakePgConnection("failed", fail_first_execute=True)
    driver = _FakePsycopg([failed], recovery_failures=3)
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    backoffs: list[float] = []
    connection = connect_postgres(
        "postgresql://vinctor:secret@db/vinctor",
        backoff=backoffs.append,
    )
    with pytest.raises(_FakeOperationalError):
        connection.execute("UPDATE durable_state SET value = 2")

    # When the next safe operation tries to recover.
    with pytest.raises(_FakeOperationalError):
        connection.execute("SELECT 1")

    # Then recovery stops after three attempts and two injected backoffs.
    assert driver.connect_calls == 4
    assert backoffs == [0.05, 0.1]


def test_postgres_concurrent_recovery_publishes_one_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given two callers reaching the same broken serialized connection.
    failed = _FakePgConnection("failed")
    failed.broken = True
    replacement = _FakePgConnection("replacement")
    entered = Event()
    release = Event()
    driver = _FakePsycopg(
        [failed, replacement],
        recovery_gate=(entered, release),
    )
    monkeypatch.setitem(sys.modules, "psycopg", driver)
    connection = connect_postgres(
        "postgresql://vinctor:secret@db/vinctor",
        backoff=lambda delay: None,
    )

    # When both operations race while the replacement factory is blocked.
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(connection.execute, "SELECT 1") for _ in range(2)]
        assert entered.wait(timeout=5)
        release.set()
        rows = [future.result(timeout=5).fetchone() for future in futures]

    # Then one factory result is published and both callers use it.
    assert rows == [(1,), (1,)]
    assert driver.connect_calls == 2
    assert replacement.statements[0] == "SELECT 1"
    assert replacement.statements[-2:] == ["SELECT 1", "SELECT 1"]
    assert any("schema_migrations" in statement for statement in replacement.statements)


class _UnavailableTransaction:
    def __enter__(self) -> _UnavailableTransaction:
        raise _FakeOperationalError(
            "postgresql://vinctor:top-secret@db/vinctor connection refused"
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        return False


class _UnavailableConnection:
    def transaction(self) -> _UnavailableTransaction:
        return _UnavailableTransaction()

    def close(self) -> None:
        pass


class _FakePostgresService:
    def close(self) -> None:
        pass


class _FakePostgresKeys:
    pass


@contextmanager
def _running_runtime(handle: ServiceRuntimeHandle) -> Iterator[None]:
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)


def _request(handle: ServiceRuntimeHandle, path: str) -> tuple[int, dict[str, str], str]:
    host, port = handle.server.server_address
    connection = HTTPConnection(host, port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        return response.status, json.loads(raw), raw
    finally:
        connection.close()


def test_postgres_readyz_fails_coarsely_when_store_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a PostgreSQL runtime whose durable connection cannot answer a probe.
    monkeypatch.setattr(
        "vinctor_service.service_runtime.connect_postgres",
        lambda dsn: _UnavailableConnection(),
    )
    # The readiness probe connects for itself (PKA-146); keep it off the network.
    monkeypatch.setattr(
        "vinctor_service.service_runtime.connect_postgres_readiness",
        lambda dsn, *, timeout_seconds: _UnavailableConnection(),
    )
    monkeypatch.setattr(
        "vinctor_service.service_runtime.PostgresV1Service",
        lambda connection: _FakePostgresService(),
    )
    monkeypatch.setattr(
        "vinctor_service.service_runtime.PostgresLocalKeyRepository",
        lambda connection: _FakePostgresKeys(),
    )
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(
            storage_backend="postgres",
            postgres_dsn="postgresql://vinctor:top-secret@db/vinctor",
            service_mode="self_hosted",
            port=0,
        )
    )

    # When an unauthenticated caller requests readiness, then liveness.
    try:
        with _running_runtime(handle):
            status, body, raw = _request(handle, "/readyz")
            live_status, live_body, _ = _request(handle, "/healthz")
    finally:
        handle.close()

    # Then readiness is unavailable and exposes no connection detail.
    assert status == 503
    assert body == {
        "status": "unavailable",
        "service": "vinctor-service",
    }
    assert "postgresql://" not in raw
    assert "top-secret" not in raw
    # ...while liveness still answers: the process is alive, only the store is
    # gone, and restarting it would only remove capacity (PKA-117).
    assert live_status == 200
    assert live_body == {
        "status": "ok",
        "service": "vinctor-service",
        "mode": "self_hosted",
    }
    assert "connection refused" not in raw
