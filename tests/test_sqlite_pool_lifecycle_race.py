from __future__ import annotations

import sqlite3
from pathlib import Path
from threading import Event, Thread

import pytest
from idempotency_sqlite_fixtures import configured_pool

from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite


def test_close_wins_blocked_replacement_and_closes_late_candidate_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "late-replacement.sqlite3"
    factory_started = Event()
    release_factory = Event()
    replacement: list[SerializedSQLiteConnection] = []
    close_counts: dict[int, int] = {}
    original_close = SerializedSQLiteConnection.close

    def record_close(connection: SerializedSQLiteConnection) -> None:
        identity = id(connection)
        close_counts[identity] = close_counts.get(identity, 0) + 1
        original_close(connection)

    def blocked_factory() -> SerializedSQLiteConnection:
        factory_started.set()
        assert release_factory.wait(timeout=5)
        candidate = connect_sqlite(database, check_same_thread=False)
        replacement.append(candidate)
        return candidate

    monkeypatch.setattr(SerializedSQLiteConnection, "close", record_close)
    pool = configured_pool(database, size=1, connection_factory=blocked_factory)
    old = pool._contexts[0]
    failures: list[BaseException] = []

    def quarantine() -> None:
        try:
            with pool.request_scope():
                assert pool.current_context is old
                assert pool.quarantine_current_context(old.generation) is True
        except BaseException as error:
            failures.append(error)

    worker = Thread(target=quarantine)
    worker.start()
    try:
        assert factory_started.wait(timeout=5)
        closer = Thread(target=pool.close)
        closer.start()
        closer.join(timeout=1)
        assert not closer.is_alive()
        release_factory.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        assert failures == []
        assert len(replacement) == 1
        candidate = replacement[0]
        with pytest.raises(sqlite3.ProgrammingError):
            candidate.execute("SELECT 1")
        pool.close()
        assert close_counts[id(old.connection)] == 1
        assert close_counts[id(candidate)] == 1
        assert pool.capacity == 0
        assert pool._contexts == []
        assert len(pool._available) == 0
        assert pool.is_ready() is False
        assert not Path(f"{database}-wal").exists()
        assert not Path(f"{database}-shm").exists()
    finally:
        release_factory.set()
        worker.join(timeout=5)
        pool.close()


def test_close_racing_request_exit_does_not_requeue_or_double_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = Event()
    release_request = Event()
    close_counts: dict[int, int] = {}
    original_close = SerializedSQLiteConnection.close

    def record_close(connection: SerializedSQLiteConnection) -> None:
        identity = id(connection)
        close_counts[identity] = close_counts.get(identity, 0) + 1
        original_close(connection)

    monkeypatch.setattr(SerializedSQLiteConnection, "close", record_close)
    pool = configured_pool(tmp_path / "request-exit.sqlite3", size=1)
    context = pool._contexts[0]

    def request() -> None:
        with pool.request_scope():
            assert pool.current_context is context
            entered.set()
            assert release_request.wait(timeout=5)

    worker = Thread(target=request)
    worker.start()
    try:
        assert entered.wait(timeout=5)
        closer = Thread(target=pool.close)
        closer.start()
        closer.join(timeout=1)
        assert not closer.is_alive()
        release_request.set()
        worker.join(timeout=5)
        assert not worker.is_alive()
        pool.close()
        assert close_counts[id(context.connection)] == 1
        assert pool.capacity == 0
        assert pool._contexts == []
        assert len(pool._available) == 0
    finally:
        release_request.set()
        worker.join(timeout=5)
        pool.close()


def test_concurrent_replenishment_builds_and_publishes_only_one_context(
    tmp_path: Path,
) -> None:
    database = tmp_path / "single-replacement.sqlite3"
    factory_started = Event()
    release_factory = Event()
    factory_calls = 0
    request_failures: list[str] = []
    readiness: list[bool] = []

    def blocked_factory() -> SerializedSQLiteConnection:
        nonlocal factory_calls
        factory_calls += 1
        factory_started.set()
        assert release_factory.wait(timeout=5)
        return connect_sqlite(database, check_same_thread=False)

    pool = configured_pool(database, size=1, connection_factory=blocked_factory)
    old = pool._contexts[0]

    def quarantine() -> None:
        with pool.request_scope():
            assert pool.quarantine_current_context(old.generation) is True

    def competing_request() -> None:
        try:
            with pool.request_scope():
                raise AssertionError("depleted pool unexpectedly leased a context")
        except RuntimeError as error:
            request_failures.append(str(error))

    first = Thread(target=quarantine)
    first.start()
    try:
        assert factory_started.wait(timeout=5)
        second = Thread(target=competing_request)
        second.start()
        second.join(timeout=1)
        assert not second.is_alive()
        probe = Thread(target=lambda: readiness.append(pool.is_ready()))
        probe.start()
        probe.join(timeout=1)
        assert not probe.is_alive()
        assert readiness == [False]
        assert request_failures == ["SQLite service pool unavailable"]
        assert factory_calls == 1
        release_factory.set()
        first.join(timeout=5)
        assert not first.is_alive()
        assert factory_calls == 1
        assert pool.capacity == 1
        assert len(pool._contexts) == len(pool._available) == 1
        assert pool._contexts[0].generation > old.generation
    finally:
        release_factory.set()
        first.join(timeout=5)
        pool.close()


def test_shared_state_has_no_connection_bound_executor_field(tmp_path: Path) -> None:
    pool = configured_pool(tmp_path / "shared-state.sqlite3", size=1)
    try:
        service = pool._contexts[0].service
        state = service.shared_state
        assert state is not None
        assert repr(state).startswith("SQLiteServiceSharedState(")
        assert not hasattr(state, "idempotency_executor")
        assert state == state
        assert service.idempotency_executor.store.conn is service.conn
    finally:
        pool.close()
