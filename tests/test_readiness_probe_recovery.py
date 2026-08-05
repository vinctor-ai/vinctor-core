"""PKA-146: a readiness worker blocked in the backend must not latch /readyz.

PKA-117 replaced the probe object once its deadline passed, but gated the worker
on ``Thread.is_alive()``. A worker blocked inside the backend call IS alive, so
no replacement was ever started and nobody serviced the new probes: every later
call created a probe, waited its deadline and returned False, while the backend
call count stayed at one for the life of the process. `/readyz` answered 503
forever and the pod stayed drained until it was restarted — the outage
amplification PKA-117 removed from liveness, reappearing on readiness.

"Returned False" is what the pre-merge review checked, and the broken code
satisfies it. These tests assert the backend is reached AGAIN, that abandoning
workers is bounded and observable, and that shutdown cannot close a connection
underneath a probe it could not stop.

Everything here runs against fakes in the default suite; the live PostgreSQL
path is tests/test_postgres_recovery_live.py.
"""

from __future__ import annotations

import json
import sys
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from http.client import HTTPConnection
from pathlib import Path
from threading import Event, Lock, Thread, current_thread
from threading import enumerate as enumerate_threads
from time import monotonic, sleep
from typing import Any

import pytest

from vinctor_service import health_checks, service_runtime, sqlite_pool
from vinctor_service.health_checks import BoundedBackendProbe
from vinctor_service.postgres_connection import (
    SerializedPostgresConnection,
    connect_postgres,
    connect_postgres_readiness,
    require_supported_libpq,
)
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import (
    PostgresReadinessProbe,
    ServiceRuntimeHandle,
    prepare_service_runtime,
)

DSN = "postgresql://vinctor:top-secret@127.0.0.1:5432/vinctor"


class _Rows:
    def fetchone(self) -> tuple[int]:
        return (1,)

    def fetchall(self) -> list[Any]:
        return []


class _WedgingStore:
    """A PostgreSQL stand-in whose first probe never returns.

    The outage the card describes: one socket read wedges while the database
    itself recovers and goes on accepting new connections. Nothing but the
    process's own refusal to ask again keeps it out of rotation.
    """

    def __init__(self) -> None:
        self.probes = 0
        self.cancels = 0
        self.closes = 0
        self.executes = 0
        self._lock = Lock()
        self._released = Event()

    def transaction(self) -> Any:
        with self._lock:
            self.probes += 1
            first = self.probes == 1
        if first:
            assert self._released.wait(timeout=30)
        return nullcontext()

    def execute(self, *args: Any, **kwargs: Any) -> _Rows:
        with self._lock:
            self.executes += 1
        return _Rows()

    def cancel_safe(self, *, timeout: float) -> None:
        with self._lock:
            self.cancels += 1

    def close(self) -> None:
        with self._lock:
            self.closes += 1

    def release(self) -> None:
        self._released.set()


class _FakeService:
    def close(self) -> None:
        return None


class _FakeKeys:
    pass


@contextmanager
def _postgres_runtime(
    store: _WedgingStore,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[ServiceRuntimeHandle]:
    monkeypatch.setattr("vinctor_service.service_runtime.connect_postgres", lambda dsn: store)
    monkeypatch.setattr(
        "vinctor_service.service_runtime.connect_postgres_readiness",
        lambda dsn, *, timeout_seconds: store,
    )
    monkeypatch.setattr(
        "vinctor_service.service_runtime.PostgresV1Service",
        lambda connection: _FakeService(),
    )
    monkeypatch.setattr(
        "vinctor_service.service_runtime.PostgresLocalKeyRepository",
        lambda connection: _FakeKeys(),
    )
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(
            storage_backend="postgres",
            postgres_dsn=DSN,
            service_mode="self_hosted",
            port=0,
        )
    )
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        yield handle
    finally:
        store.release()
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()


def _get(handle: ServiceRuntimeHandle, path: str) -> tuple[int, dict[str, Any], str]:
    host, port = handle.server.server_address
    connection = HTTPConnection(host, port, timeout=10)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        raw = response.read().decode("utf-8")
        return response.status, json.loads(raw), raw
    finally:
        connection.close()


def _readiness_workers() -> set[Thread]:
    return {
        thread
        for thread in enumerate_threads()
        if thread.name == "vinctor-readiness-probe" and thread.is_alive()
    }


def _poll_until_ready(probe: BoundedBackendProbe, timeout: float = 5.0) -> bool:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if probe():
            return True
        sleep(0.02)
    return False


def _wait_for(predicate: Any, timeout: float = 5.0) -> bool:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if predicate():
            return True
        sleep(0.02)
    return False


def test_a_wedged_backend_call_does_not_stop_later_probes_from_reaching_the_backend() -> None:
    # Given a backend whose first call never returns while these assertions run.
    released = Event()
    calls: list[int] = []
    lock = Lock()

    def check() -> bool:
        with lock:
            calls.append(1)
            first = len(calls) == 1
        if first:
            assert released.wait(timeout=30)
        return True

    probe = BoundedBackendProbe(check, timeout_seconds=0.1)
    try:
        # When the probe is called again and again.
        first = probe()
        recovered = _poll_until_ready(probe)
        with lock:
            reached = len(calls)
    finally:
        released.set()
        probe.close()

    # Then the wedged call cost one failed probe, not the process. Asserting
    # only "returned False" is what let this through: the tell is that the
    # backend was asked again at all.
    assert first is False
    assert reached > 1
    assert recovered is True


def test_readyz_returns_200_once_the_backend_answers_after_a_wedged_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a runtime whose first readiness probe wedges in the store forever.
    monkeypatch.setenv("VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS", "0.2")
    store = _WedgingStore()

    with _postgres_runtime(store, monkeypatch) as handle:
        # When readiness is probed repeatedly, as a kubelet would.
        first_status, first_body, first_raw = _get(handle, "/readyz")
        statuses = [first_status]
        deadline = monotonic() + 10.0
        while monotonic() < deadline and statuses[-1] != 200:
            sleep(0.05)
            statuses.append(_get(handle, "/readyz")[0])
        probes = store.probes

    # Then the pod comes back into rotation on its own. Before this fix the
    # store was never asked a second time and /readyz stayed 503 until restart.
    assert first_status == 503
    assert first_body == {"status": "unavailable", "service": "vinctor-service"}
    assert statuses[-1] == 200
    assert probes > 1
    # No-disclosure holds on the failing branch.
    assert "postgresql://" not in first_raw
    assert "top-secret" not in first_raw


def test_the_abandoned_worker_bound_is_enforced_and_observable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Given a store that never answers any probe, so every worker wedges.
    released = Event()
    calls: list[int] = []
    lock = Lock()

    def check() -> bool:
        with lock:
            calls.append(1)
        assert released.wait(timeout=30)
        return True

    before = _readiness_workers()
    probe = BoundedBackendProbe(check, timeout_seconds=0.05, max_abandoned_workers=2)
    try:
        # When readiness is probed well past the point where the cap is reached.
        results = [probe() for _ in range(6)]
        assert _wait_for(lambda: len(calls) >= 3)
        sleep(0.2)
        with lock:
            reached = len(calls)
        abandoned = probe.abandoned_workers
        hits = probe.abandoned_worker_limit_hits
        live = len(_readiness_workers() - before)
        # The operator line is emitted off the request path, so it is collected
        # by polling rather than assumed to have been written synchronously.
        # readouterr() consumes, so the reads are accumulated — asserting on a
        # literal here instead would make the count below assert nothing.
        collected = ""

        def _collect() -> bool:
            nonlocal collected
            collected += capsys.readouterr().err
            return "readiness probe is holding" in collected

        assert _wait_for(_collect)
        reported = collected

        # Then the wedged store costs at most the cap plus the worker in hand —
        # a store that is never coming back must not buy a thread and a driver
        # session per probe for the life of the process.
        assert results == [False] * 6
        assert abandoned == 2
        assert reached == 3
        assert live == 3
        # ...and reaching the cap is visible rather than a silent 503: three
        # probes failed closed on it, reported once for the episode.
        assert hits == 3
        assert reported.count("vinctor: readiness probe is holding") == 1
        assert "abandoned worker(s)" in reported

        # And when the store finally answers, the slots come back and so does
        # readiness — the cap must not be the new absorbing state.
        released.set()
        assert _poll_until_ready(probe) is True
        assert _wait_for(lambda: probe.abandoned_workers == 0)
    finally:
        released.set()
        probe.close()


# The escape is the point of the test: it genuinely kills the worker thread, so
# pytest's unhandled-thread-exception warning is expected output, not a defect.
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_a_dead_worker_costs_no_abandoned_slot() -> None:
    # A BaseException escape kills the worker thread. There is nothing left
    # running to abandon, so it must not spend a slot: otherwise a repeatable
    # escape exhausts the cap and latches /readyz at 503 all over again.
    calls: list[int] = []
    lock = Lock()

    def check() -> bool:
        with lock:
            calls.append(1)
            first = len(calls) == 1
        if first:
            raise KeyboardInterrupt("simulated interpreter-level escape")
        return True

    probe = BoundedBackendProbe(check, timeout_seconds=0.2, max_abandoned_workers=1)
    try:
        assert probe() is False
        assert _poll_until_ready(probe) is True
        assert probe.abandoned_workers == 0
        assert probe.abandoned_worker_limit_hits == 0
    finally:
        probe.close()


def test_abandoning_a_worker_cancels_the_backend_call_off_every_deadline_path() -> None:
    # Given a check that owns a backend handle, so it can be cancelled.
    class _CancellableCheck:
        def __init__(self) -> None:
            self.calls = 0
            self.cancel_threads: list[str] = []
            self._lock = Lock()
            self._released = Event()

        def __call__(self) -> bool:
            with self._lock:
                self.calls += 1
            assert self._released.wait(timeout=30)
            return True

        def cancel(self) -> None:
            with self._lock:
                self.cancel_threads.append(current_thread().name)
            # A real cancel makes the wedged call return and release its
            # connection instead of parking on it.
            self._released.set()

    check = _CancellableCheck()
    probe = BoundedBackendProbe(check, timeout_seconds=0.1)
    caller = current_thread().name
    try:
        # When the first probe blows its deadline and a replacement is started.
        assert probe() is False
        recovered = _poll_until_ready(probe)
        # Snapshot before close(), which cancels from the closing thread on
        # purpose: shutdown has no readiness deadline left to spend.
        cancelled_on = list(check.cancel_threads)
    finally:
        check.cancel()
        probe.close()

    # Then the expired call was cancelled, so the deadline bounds the backend
    # operation and not only the waiter...
    assert cancelled_on
    assert recovered is True
    # ...and on neither of the two threads that are inside a readiness bound:
    # not the caller's, and not the replacement worker's either — cancelling is
    # I/O, and a replacement that pays for it answers late or not at all.
    assert caller not in cancelled_on
    assert not any(name.startswith("vinctor-readiness-probe") for name in cancelled_on)
    # It runs on the reclaimer, which is neither. It needs no thread of its own
    # to stay responsive: the cancel is bounded by the driver, because the
    # Postgres backend refuses to start below libpq 17.
    assert all(name.startswith("vinctor-readiness-reclaimer") for name in cancelled_on)


def test_an_expensive_cancel_does_not_consume_any_readiness_deadline() -> None:
    # Given one wedged call — so reclamation is running — and a cancel that
    # costs far more than the readiness bound, as a serial sweep over several
    # stale connections does.
    released = Event()
    cancels: list[int] = []
    calls: list[int] = []
    lock = Lock()

    def check() -> bool:
        with lock:
            calls.append(1)
            first = len(calls) == 1
        if first:
            assert released.wait(timeout=30)
        # The backend is healthy for every later call.
        return True

    def cancel() -> None:
        with lock:
            cancels.append(1)
        sleep(0.4)

    check.cancel = cancel  # type: ignore[attr-defined]
    probe = BoundedBackendProbe(check, timeout_seconds=0.05)
    try:
        # When the first probe wedges and later probes run against the healthy
        # backend while reclamation grinds away.
        assert probe() is False
        started = monotonic()
        recovered = _poll_until_ready(probe, timeout=3.0)
        elapsed = monotonic() - started
        assert _wait_for(lambda: len(cancels) >= 1, timeout=3.0)
    finally:
        released.set()
        probe.close()

    # Then readiness answers at its own pace. Cancelling on the replacement
    # worker made every probe cost the cancel instead: with cancel > bound that
    # is a permanent 503 against a healthy backend, and a silent one — the cap
    # is never reached, so nothing is reported.
    assert recovered is True
    assert elapsed < 1.0


class _SharedConnection:
    """Stand-in for the process-wide serialized connection."""

    def __init__(self, *, ready: bool = True) -> None:
        self._ready = ready
        self.transactions = 0
        self.executes = 0

    def transaction(self) -> Any:
        self.transactions += 1
        return nullcontext()

    def execute(self, *args: Any, **kwargs: Any) -> _Rows:
        self.executes += 1
        return _Rows()

    def close(self) -> None:
        return None

    @property
    def is_ready(self) -> bool:
        return self._ready


def test_postgres_readiness_probes_its_own_connection_not_the_shared_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a runtime whose process connection and readiness connection are
    # distinct objects, so which one answers /readyz is observable.
    shared = _SharedConnection()
    dedicated = _WedgingStore()
    dedicated.release()
    opened: list[float] = []

    def connect(dsn: str, *, timeout_seconds: float) -> _WedgingStore:
        opened.append(timeout_seconds)
        return dedicated

    monkeypatch.setattr(service_runtime, "connect_postgres", lambda dsn: shared)
    monkeypatch.setattr(service_runtime, "connect_postgres_readiness", connect)
    monkeypatch.setattr(
        service_runtime,
        "PostgresV1Service",
        lambda connection: _FakeService(),
    )
    monkeypatch.setattr(
        service_runtime,
        "PostgresLocalKeyRepository",
        lambda connection: _FakeKeys(),
    )
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(
            storage_backend="postgres",
            postgres_dsn=DSN,
            service_mode="self_hosted",
            port=0,
        )
    )
    server = Thread(target=handle.server.serve_forever, daemon=True)
    server.start()
    try:
        # When readiness is probed over HTTP.
        status, body, _ = _get(handle, "/readyz")
    finally:
        handle.server.shutdown()
        server.join(timeout=5)
        handle.close()

    # Then the store queries ran on the probe's own connection: probing them on
    # the shared one took the lock every enforce request needs, so a slow store
    # became a stalled service and a wedged probe pinned that connection.
    assert status == 200
    assert body == {"status": "ready", "service": "vinctor-service"}
    assert dedicated.probes == 1
    # The idempotency-readiness queries — the expensive part — never touch the
    # shared connection...
    assert dedicated.executes >= 3
    # ...and the shared one is used for exactly one thing: proving THIS process
    # can still serve, which no other connection can answer. One transaction,
    # one statement. Skipping it entirely reports 200 on a dead serving
    # connection, because `is_ready` only turns false once something has tried
    # to use it.
    assert shared.transactions == 1
    assert shared.executes == 1
    # It is opened with the readiness bound, not with the driver's defaults.
    assert opened == [service_runtime.resolve_readiness_timeout_seconds()]


def test_postgres_readiness_fails_closed_when_the_runtime_connection_is_quarantined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A quarantined runtime connection means the process cannot serve, whatever
    # the store would say. Readiness must not report ready off its own healthy
    # side connection.
    shared = _SharedConnection(ready=False)
    dedicated = _WedgingStore()
    dedicated.release()
    monkeypatch.setattr(
        service_runtime,
        "connect_postgres_readiness",
        lambda dsn, *, timeout_seconds: dedicated,
    )
    probe = PostgresReadinessProbe(shared, DSN, None, timeout_seconds=0.5)
    try:
        assert probe() is False
    finally:
        probe.close()

    assert dedicated.probes == 0


def test_readiness_connection_carries_driver_and_server_deadlines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a driver that records how the readiness connection is opened.
    statements: list[str] = []
    recorded: dict[str, Any] = {}

    class _FakeConnection:
        def execute(self, statement: str) -> None:
            statements.append(statement)

        def close(self) -> None:
            return None

    class _FakePq:
        @staticmethod
        def version() -> int:
            return 170000

    class _FakePsycopg:
        pq = _FakePq()
        capabilities = _FakeCapabilities(cancel_safe=True)
        __version__ = "3.2.0"

        def connect(self, dsn: str, **kwargs: Any) -> _FakeConnection:
            recorded["dsn"] = dsn
            recorded["kwargs"] = kwargs
            return _FakeConnection()

    monkeypatch.setitem(sys.modules, "psycopg", _FakePsycopg())

    # When the readiness connection is opened under a 2s bound.
    connect_postgres_readiness(DSN, timeout_seconds=2.0)

    # Then the bound is enforced by the driver and the server, not only by the
    # caller: a deadline that bounds the waiter alone leaves the query running
    # and its session pinned, which is how a wedged probe kept a backend
    # connection for the life of the process (PKA-146).
    assert recorded["kwargs"]["connect_timeout"] == 2
    assert recorded["kwargs"]["keepalives"] == 1
    assert recorded["kwargs"]["keepalives_idle"] == 2
    assert recorded["kwargs"]["autocommit"] is True
    assert statements == [
        "SET statement_timeout = 2000",
        "SET lock_timeout = 2000",
        "SET idle_in_transaction_session_timeout = 2000",
    ]
    # Issued as SET, not as libpq `options`, so an operator's own options in the
    # DSN are not clobbered.
    assert "options" not in recorded["kwargs"]
    # The only bound a client can enforce against a black-holed socket:
    # statement_timeout is the server's, keepalives do not fire with data
    # unacknowledged, and connect_timeout covers the handshake only.
    assert recorded["kwargs"]["tcp_user_timeout"] == 2000


def test_serialized_postgres_readiness_flag_does_not_wait_on_the_connection_lock() -> None:
    # Given a connection whose lock is held, as it is for every enforce
    # transaction.
    connection = SerializedPostgresConnection(object())
    answers: list[bool] = []

    with connection.lock:
        reader = Thread(target=lambda: answers.append(connection.is_ready))
        reader.start()
        reader.join(timeout=2)
        blocked = reader.is_alive()

    reader.join(timeout=5)

    # Then readiness can still read it. Taking the lock here would let one
    # wedged request park every readiness worker in turn — PKA-146 in a new
    # place — and the flag is two attribute reads whose torn states all report
    # False, so it fails closed.
    assert blocked is False
    assert answers == [True]


def test_postgres_shutdown_does_not_close_a_connection_under_an_in_flight_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a probe wedged inside the store.
    store = _WedgingStore()
    monkeypatch.setattr(
        service_runtime,
        "connect_postgres_readiness",
        lambda dsn, *, timeout_seconds: store,
    )
    probe = PostgresReadinessProbe(_SharedConnection(), DSN, None, timeout_seconds=0.2)
    results: list[bool] = []
    worker = Thread(target=lambda: results.append(probe()), daemon=True)
    worker.start()
    assert _wait_for(lambda: store.probes == 1)

    # When shutdown runs while the probe is still inside the call.
    probe.close()
    closed_during_call = store.closes

    # Then the connection the call is using was cancelled, not closed: closing
    # it here is closing a handle underneath a live statement, and close()
    # cannot join a worker the driver is holding (PKA-146).
    assert closed_during_call == 0
    assert store.cancels >= 1

    store.release()
    worker.join(timeout=10)
    assert not worker.is_alive()

    # The call that owned it disposes of it when it returns, exactly once.
    assert results == [True]
    assert store.closes == 1


def test_sqlite_shutdown_does_not_close_the_database_under_an_in_flight_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a running SQLite runtime.
    monkeypatch.setenv("VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS", "0.2")
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0)
    )
    in_check = Event()
    release = Event()
    finished = Event()
    failures: list[str] = []
    real_ready = sqlite_pool.sqlite_idempotency_ready

    def blocking_ready(conn: Any, keyring: Any, **kwargs: Any) -> bool:
        # Patched after startup, so only the readiness probe blocks here.
        in_check.set()
        assert release.wait(timeout=30)
        try:
            conn.execute("SELECT 1").fetchone()
            return real_ready(conn, keyring, **kwargs)
        except BaseException as error:  # noqa: BLE001 - recorded, then re-raised
            failures.append(f"{type(error).__name__}: {error}")
            raise
        finally:
            finished.set()

    monkeypatch.setattr(sqlite_pool, "sqlite_idempotency_ready", blocking_ready)
    server = Thread(target=handle.server.serve_forever, daemon=True)
    server.start()
    requester = Thread(target=lambda: _get(handle, "/readyz"), daemon=True)
    requester.start()
    try:
        assert in_check.wait(timeout=10)

        # When shutdown runs while the readiness worker is mid-statement.
        handle.server.shutdown()
        server.join(timeout=5)
        handle.close()
    finally:
        release.set()
        requester.join(timeout=10)

    # Then nothing operated on a closed database. close() joins the worker only
    # briefly and then returns, so the runtime used to close the pooled
    # connection the probe was still using: reproduced as
    # `sqlite3.ProgrammingError: Cannot operate on a closed database`. The wait
    # is on the WORKER, not on the request: the request was answered 503 at its
    # deadline long before shutdown, and asserting without it checks nothing.
    assert finished.wait(timeout=10)
    assert failures == []


# --- Invariants the independent review named. Each test fails if its invariant
# --- is violated, and each drives CONCURRENT probes where the defect needs them.


class _RecoverableBackend:
    """A PostgreSQL stand-in that wedges during an outage and answers after it.

    A wedged call returns ONLY when cancelled, never of its own accord — which
    is the point: recovery must not wait on the store to finally answer a call
    it already swallowed. `cancel_safe` reaches it the way psycopg does, over a
    connection of its own, so it works as soon as the store is reachable again.
    """

    def __init__(self) -> None:
        self.outage = True
        self.opened = 0
        self.live = 0
        self.max_live = 0
        self.cancelled = 0
        self.lock = Lock()
        self.connections: list[_RecoverableConnection] = []

    def connect(self, dsn: str, *, timeout_seconds: float) -> _RecoverableConnection:
        connection = _RecoverableConnection(self)
        with self.lock:
            self.opened += 1
            self.live += 1
            self.max_live = max(self.max_live, self.live)
            self.connections.append(connection)
        return connection

    def recover(self) -> None:
        with self.lock:
            self.outage = False


class _Cancelled(RuntimeError):
    pass


class _RecoverableConnection:
    def __init__(self, backend: _RecoverableBackend) -> None:
        self._backend = backend
        self._released = Event()
        self.cancel_attempts = 0
        self.cancelled = False
        self.closed = False

    def transaction(self) -> Any:
        with self._backend.lock:
            wedged = self._backend.outage
        if wedged:
            assert self._released.wait(timeout=30)
            raise _Cancelled("readiness query cancelled")
        return nullcontext()

    def execute(self, *args: Any, **kwargs: Any) -> _Rows:
        return _Rows()

    def cancel_safe(self, *, timeout: float) -> None:
        # A cancel request travels over its own connection, so during a total
        # outage it cannot be delivered either. psycopg RAISES in that case
        # (it opens a new connection to send the request, and a down store
        # refuses it) and raises CancellationTimeout at its own bound. Modelling
        # a failed cancel as a silent return makes it indistinguishable from a
        # delivered one — which is precisely the confusion under test.
        with self._backend.lock:
            self.cancel_attempts += 1
            if self._backend.outage:
                raise RuntimeError("cancel request could not be delivered")
            self._backend.cancelled += 1
        self.cancelled = True
        self._released.set()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        with self._backend.lock:
            self._backend.live -= 1


def test_a_healthy_backend_answers_200_even_with_the_abandoned_cap_saturated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given an outage that has swallowed every worker the cap allows.
    backend = _RecoverableBackend()
    monkeypatch.setattr(service_runtime, "connect_postgres_readiness", backend.connect)
    check = PostgresReadinessProbe(_SharedConnection(), DSN, None, timeout_seconds=0.05)
    probe = BoundedBackendProbe(check, timeout_seconds=0.05, max_abandoned_workers=2)
    try:
        assert _wait_for(lambda: [probe(), probe.abandoned_workers == 2][1], timeout=5.0)
        # Now ask again: these are the probes that meet the cap itself.
        assert [probe(), probe()] == [False, False]
        assert probe.abandoned_worker_limit_hits >= 2
        saturated_calls = backend.opened
        # Let the reclaimer sweep the wedged calls at least once WHILE the store
        # is still down, so every one of them has had a cancel attempted and
        # failed. Recovering immediately leaves a call young enough to have
        # escaped the first sweep, and the recovery is then attributable to that
        # accident rather than to the retry.
        sleep(1.0)
        swept = [connection.cancel_attempts for connection in backend.connections]

        # When the database becomes completely healthy, while every wedged call
        # is still wedged.
        backend.recover()

        # Then readiness comes back without any of those calls having answered.
        # Refusing to start work until one of them does is the absorbing state
        # that made the cap PKA-146 with a bigger budget.
        started = monotonic()
        recovered = _poll_until_ready(probe, timeout=10.0)
        elapsed = monotonic() - started
    finally:
        probe.close()
        check.close()

    # PREMISE: the cap was saturated and every wedged call had already had a
    # cancel attempted and fail before the store came back.
    assert saturated_calls >= 3
    assert all(attempts >= 1 for attempts in swept), swept
    assert recovered is True
    assert elapsed < 8.0
    # ATTRIBUTION: the recovery came from the mechanism under test, not from a
    # call that happened to slip through. A cancel was DELIVERED after
    # recovery — meaning a previously failed attempt was retried — and a fresh
    # probe connection was opened once the slot came back.
    assert backend.cancelled >= 1
    assert backend.opened > saturated_calls


def test_readiness_holds_at_most_one_backend_connection_per_allowed_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a total outage driven hard enough to saturate the cap.
    backend = _RecoverableBackend()
    monkeypatch.setattr(service_runtime, "connect_postgres_readiness", backend.connect)
    check = PostgresReadinessProbe(_SharedConnection(), DSN, None, timeout_seconds=0.05)
    probe = BoundedBackendProbe(check, timeout_seconds=0.05, max_abandoned_workers=2)
    try:
        for _ in range(12):
            probe()
        live = backend.max_live
    finally:
        probe.close()
        check.close()

    # Then the session count never exceeds the cap plus the worker in hand...
    assert live <= 3
    # ...and it is demonstrably more than one. Every overlapping probe opens its
    # own connection — the idle one is taken OUT of the slot, not shared — so
    # "one extra session per service process" understated the real cost.
    assert live > 1


def test_concurrent_probes_each_keep_their_sqlite_connection_through_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given two readiness probes in flight at once — which is what the bounded
    # probe produces the moment it replaces a wedged worker.
    monkeypatch.setenv("VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS", "0.2")
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0)
    )
    entered = Lock()
    in_check: list[Event] = [Event(), Event()]
    release = Event()
    finished: list[Event] = [Event(), Event()]
    failures: list[str] = []
    order: list[int] = []
    real_ready = sqlite_pool.sqlite_idempotency_ready

    def blocking_ready(conn: Any, keyring: Any, **kwargs: Any) -> bool:
        with entered:
            index = len(order)
            order.append(index)
        if index > 1:
            return real_ready(conn, keyring, **kwargs)
        in_check[index].set()
        assert release.wait(timeout=30)
        try:
            conn.execute("SELECT 1").fetchone()
            return real_ready(conn, keyring, **kwargs)
        except BaseException as error:  # noqa: BLE001 - recorded, then re-raised
            failures.append(f"probe {index}: {type(error).__name__}: {error}")
            raise
        finally:
            finished[index].set()

    monkeypatch.setattr(sqlite_pool, "sqlite_idempotency_ready", blocking_ready)
    server = Thread(target=handle.server.serve_forever, daemon=True)
    server.start()
    try:
        first = Thread(target=lambda: _get(handle, "/readyz"), daemon=True)
        first.start()
        assert in_check[0].wait(timeout=10)
        # Wait for the first request to be answered at its deadline. Only a
        # request arriving after that finds the probe expired, abandons the
        # wedged worker and starts a replacement — which is what puts a SECOND
        # probe on a SECOND context.
        first.join(timeout=10)
        assert not first.is_alive()
        second = Thread(target=lambda: _get(handle, "/readyz"), daemon=True)
        second.start()
        assert in_check[1].wait(timeout=10)

        # When shutdown runs with both still holding a pooled connection.
        handle.server.shutdown()
        server.join(timeout=5)
        handle.close()
    finally:
        release.set()
        for thread in (server,):
            thread.join(timeout=5)

    # Then NEITHER probe was left on a closed database. A single-slot
    # reservation records only the newest borrower, so the older one's
    # connection is closed underneath it — the two halves of this fix
    # cancelling each other out.
    assert finished[0].wait(timeout=10)
    assert finished[1].wait(timeout=10)
    assert failures == []


def test_sqlite_readiness_interrupts_a_wedged_probe_through_the_real_wiring(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # SQLite has an exact analogue of the PostgreSQL cancel, and the runtime
    # wired `pool.is_ready` — a bound method, which carries no `cancel` — so the
    # bounded probe's hook was silently unused on this backend. That is not
    # cosmetic: SQLite's busy timeout is 5s under a 2s readiness bound, so
    # ordinary write contention outlives the deadline and spends a slot.
    #
    # Driven through prepare_service_runtime and real HTTP so the WIRING is
    # under test, not just the pool method.
    monkeypatch.setenv("VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS", "0.2")
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0)
    )
    outcome: list[str] = []
    running = Event()
    real_ready = sqlite_pool.sqlite_idempotency_ready

    def slow_ready(conn: Any, keyring: Any, **kwargs: Any) -> bool:
        if outcome:
            return real_ready(conn, keyring, **kwargs)
        running.set()
        try:
            # A genuinely long local statement — the SQLite equivalent of a
            # query the readiness bound has already given up on. Only
            # interrupt() ends it early.
            conn.execute(
                "WITH RECURSIVE s(x) AS ("
                "SELECT 1 UNION ALL SELECT x + 1 FROM s WHERE x < 60000000"
                ") SELECT count(*) FROM s"
            ).fetchone()
        except BaseException as error:  # noqa: BLE001 - the outcome under test
            outcome.append(f"{type(error).__name__}: {error}")
            raise
        else:
            outcome.append("completed")
        return real_ready(conn, keyring, **kwargs)

    monkeypatch.setattr(sqlite_pool, "sqlite_idempotency_ready", slow_ready)
    server = Thread(target=handle.server.serve_forever, daemon=True)
    server.start()
    try:
        first = Thread(target=lambda: _get(handle, "/readyz"), daemon=True)
        first.start()
        assert running.wait(timeout=10)
        first.join(timeout=10)
        # A request arriving after the deadline abandons the wedged worker,
        # which is what asks for the cancel.
        _get(handle, "/readyz")
        interrupted = _wait_for(lambda: bool(outcome), timeout=10.0)
    finally:
        handle.server.shutdown()
        server.join(timeout=5)
        handle.close()

    # Then the wedged statement was ended, not waited out.
    assert interrupted, "the wedged SQLite readiness statement was never interrupted"
    assert "interrupt" in outcome[0].lower(), outcome


def test_cancellation_reaches_a_wedged_call_however_slow_its_connect_was(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A readiness connection costs a TCP handshake plus three SET round-trips
    # before the call can register its connection. Stamping the call's age after
    # that made it younger than the bound at exactly the moment it is
    # abandoned, so the cancel issued for it skipped it and the session stayed
    # pinned. The FIRST abandonment is the common case, so this was the usual
    # outcome, not an edge one.
    #
    # Cancel is driven directly, once, at the moment BoundedBackendProbe would
    # abandon the call. Going through the reclaimer instead would hide the bug:
    # it retries, so a cancel that misses on the sweep it was raised for lands
    # on the next one.
    bound = 0.2
    for connect_cost in (0.0, 0.05, 0.15):
        backend = _RecoverableBackend()

        def slow_connect(
            dsn: str,
            *,
            timeout_seconds: float,
            _backend: _RecoverableBackend = backend,
            _cost: float = connect_cost,
        ) -> _RecoverableConnection:
            sleep(_cost)
            return _backend.connect(dsn, timeout_seconds=timeout_seconds)

        monkeypatch.setattr(service_runtime, "connect_postgres_readiness", slow_connect)
        check = PostgresReadinessProbe(_SharedConnection(), DSN, None, timeout_seconds=bound)
        started = monotonic()
        worker = Thread(target=check, daemon=True)
        worker.start()
        try:
            assert _wait_for(
                lambda _backend=backend: bool(_backend.connections),  # noqa: B008
                timeout=5.0,
            )
            # Wait out the readiness bound, which is when the call is abandoned.
            sleep(max(bound - (monotonic() - started), 0.0) + 0.01)
            check.cancel()
            attempts = backend.connections[0].cancel_attempts
        finally:
            backend.recover()
            check.cancel()
            worker.join(timeout=10)
            check.close()

        assert attempts >= 1, (
            f"the cancel raised for the wedged call skipped it (connect cost {connect_cost}s)"
        )


def test_a_failed_replacement_start_still_reclaims_the_abandoned_call() -> None:
    # Abandoning increments the slot count and hands cancellation to the
    # reclaimer. Doing it on the replacement worker instead meant a replacement
    # that could not start — thread exhaustion — left the wedged call with
    # nobody to cancel it, and the slot spent for good.
    released = Event()
    cancels: list[int] = []
    refusals: list[str] = []
    lock = Lock()
    real_thread = health_checks.Thread

    class _FlakyThread(real_thread):  # type: ignore[misc, valid-type]
        def start(self) -> None:
            # Refuse by ROLE, not by call ordinal. Counting starts globally
            # meant the ordinal the test refused was never reached inside the
            # window, so this ran green having exercised nothing.
            if self.name == "vinctor-readiness-probe" and not refusals:
                with lock:
                    refusals.append(self.name)
                raise RuntimeError("can't start new thread")
            super().start()

    def check() -> bool:
        assert released.wait(timeout=30)
        return True

    def cancel() -> None:
        with lock:
            cancels.append(1)

    check.cancel = cancel  # type: ignore[attr-defined]
    probe = BoundedBackendProbe(check, timeout_seconds=0.05, max_abandoned_workers=2)
    try:
        assert probe() is False
        with health_checks_thread(_FlakyThread):
            assert probe() is False
        reclaimed = _wait_for(lambda: len(cancels) >= 1, timeout=5.0)
    finally:
        released.set()
        probe.close()

    # PREMISE: a replacement start was actually refused. Without this the test
    # passes on code that never meets the condition it claims to cover.
    assert refusals == ["vinctor-readiness-probe"]
    assert reclaimed


def test_the_reclaimer_keeps_retrying_while_a_call_stays_wedged() -> None:
    # Retrying is the load-bearing half of recovery: a cancel cannot be
    # delivered while the store is unreachable, so one sweep is not enough. This
    # pins it ALONE — no probe is called after the abandonment, so the wake that
    # hitting the cap performs cannot stand in for the retry and hide its loss.
    released = Event()
    cancels: list[float] = []
    lock = Lock()

    def check() -> bool:
        assert released.wait(timeout=30)
        return True

    def cancel() -> None:
        with lock:
            cancels.append(monotonic())

    check.cancel = cancel  # type: ignore[attr-defined]
    probe = BoundedBackendProbe(check, timeout_seconds=0.1, max_abandoned_workers=4)
    try:
        assert probe() is False
        assert probe() is False  # abandons the wedged worker; starts reclaiming
        swept = _wait_for(lambda: len(cancels) >= 3, timeout=5.0)
        with lock:
            sweeps = len(cancels)
    finally:
        released.set()
        probe.close()

    # PREMISE: only two probe calls were made, so every sweep after the first
    # came from the reclaimer's own loop.
    assert swept, f"the reclaimer swept {sweeps} time(s) and then stopped"
    assert sweeps >= 3


@contextmanager
def health_checks_thread(replacement: Any) -> Iterator[None]:
    original = health_checks.Thread
    health_checks.Thread = replacement
    try:
        yield
    finally:
        health_checks.Thread = original


def test_a_just_started_sqlite_probe_is_not_interrupted(tmp_path: Path) -> None:
    # interrupt() is connection-wide and irreversible for the statement it hits.
    # Firing it at every probe in flight aborts the healthy replacement probe
    # that a sweep runs alongside by definition — flipping a working /readyz to
    # 503 on every sweep. Only calls past the bound may be interrupted.
    #
    # The probe must be inside a real SQLite statement when the sweep fires:
    # interrupt() aborts a running statement, so a probe parked on an Event is
    # not exercising it at all.
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0)
    )
    pool = handle.sqlite_pool
    assert pool is not None
    probe = sqlite_pool.SQLiteReadinessProbe(pool, timeout_seconds=30.0)
    running = Event()
    outcome: list[str] = []
    ages: list[float] = []
    durations: list[float] = []
    real_ready = sqlite_pool.sqlite_idempotency_ready

    def slow_ready(conn: Any, keyring: Any, **kwargs: Any) -> bool:
        started = monotonic()
        running.set()
        try:
            conn.execute(
                "WITH RECURSIVE s(x) AS ("
                "SELECT 1 UNION ALL SELECT x + 1 FROM s WHERE x < 12000000"
                ") SELECT count(*) FROM s"
            ).fetchone()
        except BaseException as error:  # noqa: BLE001 - the outcome under test
            outcome.append(f"{type(error).__name__}: {error}")
            raise
        durations.append(monotonic() - started)
        outcome.append("completed")
        return real_ready(conn, keyring, **kwargs)

    worker = Thread(target=probe, daemon=True)
    try:
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(sqlite_pool, "sqlite_idempotency_ready", slow_ready)
            started = monotonic()
            worker.start()
            assert running.wait(timeout=10)
            # A reclaimer sweep lands while this probe is far inside its bound.
            ages.append(monotonic() - started)
            probe.cancel()
            worker.join(timeout=30)
    finally:
        worker.join(timeout=30)
        handle.close()

    # PREMISE: the probe was genuinely mid-statement and far younger than the
    # bound when the sweep fired — otherwise this asserts nothing.
    assert ages and ages[0] < 30.0, ages
    assert durations and durations[0] > 0.05, durations
    assert outcome == ["completed"], outcome


def test_hitting_the_cap_starts_a_reclaimer_that_could_not_start_earlier() -> None:
    # At the cap no abandonment happens, so the abandonment-wake cannot run: if
    # the cap does not ask for reclamation too, a reclaimer that failed to start
    # while slots were being spent is never started at all, nothing cancels, and
    # the cap absorbs. Thread exhaustion is exactly when this bites.
    released = Event()
    cancels: list[int] = []
    refusals: list[str] = []
    lock = Lock()
    real_thread = health_checks.Thread

    class _FlakyThread(real_thread):  # type: ignore[misc, valid-type]
        def start(self) -> None:
            # Refuse the reclaimer for every abandonment-wake (there are two
            # before the cap is reached), leaving the cap-wake as the only
            # remaining opportunity.
            if self.name == "vinctor-readiness-reclaimer":
                with lock:
                    if len(refusals) < 2:
                        refusals.append(self.name)
                        raise RuntimeError("can't start new thread")
            super().start()

    def check() -> bool:
        assert released.wait(timeout=30)
        return True

    def cancel() -> None:
        with lock:
            cancels.append(1)

    check.cancel = cancel  # type: ignore[attr-defined]
    probe = BoundedBackendProbe(check, timeout_seconds=0.05, max_abandoned_workers=2)
    try:
        with health_checks_thread(_FlakyThread):
            for _ in range(6):
                probe()
            reclaimed = _wait_for(lambda: len(cancels) >= 1, timeout=5.0)
            at_cap = probe.abandoned_worker_limit_hits
    finally:
        released.set()
        probe.close()

    # PREMISE: both abandonment-wakes really were refused, and the cap really
    # was reached — otherwise the cap-wake is not what is under test.
    assert len(refusals) == 2
    assert at_cap >= 1
    assert reclaimed


def test_readiness_fails_closed_while_the_serving_connection_is_dead(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The probe's own connection being healthy says the STORE is up; it says
    # nothing about whether this process can serve. `is_ready` turns false only
    # once something has tried to use the serving connection, so answering from
    # the flag alone reports 200 through a dead serving connection — a fail-open
    # on the endpoint whose contract is to fail closed.
    class _DeadThenHealing(_SharedConnection):
        def __init__(self) -> None:
            super().__init__()
            self.attempts = 0

        def transaction(self) -> Any:
            self.attempts += 1
            self.transactions += 1
            if self.attempts == 1:
                # What a terminated backend does on next use, before the
                # wrapper has reconnected.
                raise RuntimeError("server closed the connection unexpectedly")
            return nullcontext()

    shared = _DeadThenHealing()
    dedicated = _WedgingStore()
    dedicated.release()
    monkeypatch.setattr(service_runtime, "connect_postgres", lambda dsn: shared)
    monkeypatch.setattr(
        service_runtime,
        "connect_postgres_readiness",
        lambda dsn, *, timeout_seconds: dedicated,
    )
    monkeypatch.setattr(service_runtime, "PostgresV1Service", lambda connection: _FakeService())
    monkeypatch.setattr(
        service_runtime,
        "PostgresLocalKeyRepository",
        lambda connection: _FakeKeys(),
    )
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(
            storage_backend="postgres",
            postgres_dsn=DSN,
            service_mode="self_hosted",
            port=0,
        )
    )
    server = Thread(target=handle.server.serve_forever, daemon=True)
    server.start()
    try:
        first = _get(handle, "/readyz")[0]
        recovered = _get(handle, "/readyz")[0]
    finally:
        handle.server.shutdown()
        server.join(timeout=5)
        handle.close()

    # PREMISE: the store itself was reachable throughout, so a 503 here can only
    # have come from the serving connection.
    assert dedicated.probes >= 1
    assert first == 503
    # ...and using it is also what reconnects it, so the process returns to
    # rotation by itself rather than staying drained with a healthy database.
    assert recovered == 200


def test_a_failed_cancel_is_retried_on_the_next_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A cancel opens a NEW connection to send its request, so it fails whenever
    # the store is down — the normal case during the outage this exists for, not
    # an exotic one. Marking the call handled on ATTEMPT made every later sweep
    # skip it, so the retry loop the whole design rests on never ran again.
    backend = _RecoverableBackend()
    monkeypatch.setattr(service_runtime, "connect_postgres_readiness", backend.connect)
    check = PostgresReadinessProbe(_SharedConnection(), DSN, None, timeout_seconds=0.05)
    worker = Thread(target=check, daemon=True)
    worker.start()
    try:
        assert _wait_for(lambda: bool(backend.connections), timeout=5.0)
        wedged = backend.connections[0]
        sleep(0.1)

        # Sweep once while the store is down: the cancel is attempted and fails.
        check.cancel()
        after_failure = wedged.cancel_attempts
        delivered_after_failure = backend.cancelled

        # The store comes back. The next sweep must try this call AGAIN.
        backend.recover()
        check.cancel()
        assert _wait_for(lambda: backend.cancelled >= 1, timeout=5.0)
        retried = wedged.cancel_attempts
    finally:
        backend.recover()
        check.cancel()
        worker.join(timeout=10)
        check.close()

    # PREMISE: the first sweep really did attempt and fail.
    assert after_failure == 1
    assert delivered_after_failure == 0
    # ATTRIBUTION: the SAME call was attempted again and that retry is what
    # delivered the cancel — not some other connection.
    assert retried >= 2
    assert wedged.cancelled is True
    assert backend.cancelled >= 1


def test_reporting_the_cap_does_not_block_readyz() -> None:
    # The operator line for the cap was written to stderr while holding the lock
    # that every /readyz call takes. A stderr that blocks — a stalled log
    # collector is enough — then blocks the endpoint, with no bound of its own:
    # the same delegated-bound mistake as the rest of this card, in the place it
    # is least expected.
    released = Event()
    blocking = Event()
    writes: list[str] = []

    class _BlockingStderr:
        def write(self, text: str) -> int:
            writes.append(text)
            blocking.set()
            assert released.wait(timeout=30)
            return len(text)

        def flush(self) -> None:
            return None

    def check() -> bool:
        assert released.wait(timeout=30)
        return True

    probe = BoundedBackendProbe(check, timeout_seconds=0.05, max_abandoned_workers=1)
    original = health_checks.sys.stderr
    try:
        # Saturate the cap first, with a normal stderr.
        assert _wait_for(lambda: [probe(), probe.abandoned_workers == 1][1], timeout=5.0)
        health_checks.sys.stderr = _BlockingStderr()  # type: ignore[assignment]
        started = monotonic()
        answered = probe()
        elapsed = monotonic() - started
    finally:
        health_checks.sys.stderr = original
        released.set()
        probe.close()

    # PREMISE: the blocking write really was reached on this path.
    assert blocking.is_set(), "the cap report never fired, so nothing was under test"
    assert answered is False
    # /readyz answers at its own bound regardless of what the log pipeline does.
    assert elapsed < 1.0


class _FakePq:
    def __init__(self, version: int) -> None:
        self._version = version

    def version(self) -> int:
        return self._version


class _FakeCapabilities:
    """psycopg's own capability object, which reports BOTH halves."""

    def __init__(self, *, cancel_safe: bool) -> None:
        self._cancel_safe = cancel_safe

    def has_cancel_safe(self, check: bool = False) -> bool:
        if self._cancel_safe:
            return True
        if check:
            raise RuntimeError("the feature 'Connection.cancel_safe()' is not available")
        return False


class _FakePsycopgModule:
    def __init__(
        self,
        version: int,
        *,
        capabilities: bool = True,
        cancel_safe: bool = True,
    ) -> None:
        self.pq = _FakePq(version)
        self.__version__ = "3.2.0" if capabilities else "3.1.20"
        if capabilities:
            self.capabilities = _FakeCapabilities(cancel_safe=cancel_safe)
        self.connects: list[str] = []
        self.OperationalError = RuntimeError

    def connect(self, dsn: str, **kwargs: Any) -> Any:
        self.connects.append(dsn)
        raise AssertionError("connect must not be reached on an unsupported driver")


def test_postgres_backend_refuses_to_start_below_libpq_17(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Below libpq 17 psycopg discards cancel_safe's timeout and falls back to a
    # blocking PQcancel, so a wedged readiness probe can never be reclaimed and
    # /readyz stays unavailable after the database has recovered. That is a
    # platform requirement, not a degraded mode: refuse, the way this service
    # refuses a schema newer than the binary.
    fake = _FakePsycopgModule(160008, cancel_safe=False)
    monkeypatch.setitem(sys.modules, "psycopg", fake)

    with pytest.raises(RuntimeError) as raised:
        connect_postgres(DSN)

    message = str(raised.value)
    assert "cancel_safe" in message
    # Names the detected version, so an operator can act on it.
    assert "16.8" in message
    # PREMISE / ATTRIBUTION: the refusal came from the version check, not from a
    # connection that happened to fail — nothing was dialled.
    assert fake.connects == []


def test_a_supported_libpq_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    # The floor must not be so eager that a supported build is rejected.
    monkeypatch.setitem(sys.modules, "psycopg", _FakePsycopgModule(170000))
    require_supported_libpq()
    monkeypatch.setitem(sys.modules, "psycopg", _FakePsycopgModule(180000))
    require_supported_libpq()


def test_the_sqlite_backend_never_consults_libpq(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # SQLite must be unaffected by a Postgres-only platform requirement — this
    # package installs without the [postgres] extra at all.
    def explode() -> None:
        raise AssertionError("the SQLite backend must not require libpq")

    monkeypatch.setattr(service_runtime, "connect_postgres", explode)
    monkeypatch.setattr(
        "vinctor_service.postgres_connection.require_supported_libpq",
        explode,
    )
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0)
    )
    server = Thread(target=handle.server.serve_forever, daemon=True)
    server.start()
    try:
        status, body, _ = _get(handle, "/readyz")
    finally:
        handle.server.shutdown()
        server.join(timeout=5)
        handle.close()

    assert status == 200
    assert body["status"] == "ready"


def test_postgres_backend_refuses_on_psycopg_without_cancel_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The floor must check the CAPABILITY, not a proxy for it. cancel_safe() is
    # a psycopg 3.2 API, and libpq's version says nothing about whether it
    # exists: on psycopg 3.1 against libpq 18 the libpq check passes, the method
    # is simply absent, every cancel raises AttributeError into a `return False`
    # and the abandoned-worker cap never drains — PKA-146 again, silently.
    fake = _FakePsycopgModule(180000, capabilities=False)
    monkeypatch.setitem(sys.modules, "psycopg", fake)

    with pytest.raises(RuntimeError) as raised:
        connect_postgres(DSN)

    message = str(raised.value)
    assert "psycopg 3.2" in message
    # PREMISE: libpq itself was fine, so only the driver API can have refused it.
    assert fake.pq.version() >= 170000
    # ATTRIBUTION: refused before dialling, by the check and not by a failed connect.
    assert fake.connects == []


def test_the_readiness_connector_enforces_the_floor_on_its_own(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Public re-export (vinctor_service.postgres), so it must not depend on
    # connect_postgres having been called first.
    fake = _FakePsycopgModule(180000, capabilities=False)
    monkeypatch.setitem(sys.modules, "psycopg", fake)

    with pytest.raises(RuntimeError):
        connect_postgres_readiness(DSN, timeout_seconds=1.0)

    assert fake.connects == []


def test_a_confirmed_cancel_is_not_repeated_on_the_next_sweep(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # `cancelled` exists to stop a delivered cancel being re-sent every sweep for
    # as long as the wedged call lives. Nothing pinned that direction, so
    # deleting the assignment left the suite green: the flag was write-only.
    backend = _RecoverableBackend()
    backend.recover()  # healthy store: a cancel is delivered on the first try
    monkeypatch.setattr(service_runtime, "connect_postgres_readiness", backend.connect)
    check = PostgresReadinessProbe(_SharedConnection(), DSN, None, timeout_seconds=0.05)

    wedge = Event()
    real_transaction = _RecoverableConnection.transaction

    def wedged_transaction(self: Any) -> Any:
        if not wedge.is_set():
            wedge.set()
            assert self._released.wait(timeout=30)
            raise _Cancelled("readiness query cancelled")
        return real_transaction(self)

    monkeypatch.setattr(_RecoverableConnection, "transaction", wedged_transaction)
    worker = Thread(target=check, daemon=True)
    worker.start()
    try:
        assert _wait_for(lambda: bool(backend.connections), timeout=5.0)
        wedged = backend.connections[0]
        sleep(0.1)

        check.cancel()
        after_first = wedged.cancel_attempts
        # PREMISE: the first sweep actually delivered it.
        assert backend.cancelled >= 1

        # A second sweep, with the call still registered.
        check.cancel()
        after_second = wedged.cancel_attempts
    finally:
        wedge.set()
        wedged.cancel_safe(timeout=1.0)
        worker.join(timeout=10)
        check.close()

    assert after_first == 1
    # ATTRIBUTION: the second sweep skipped it because it was CONFIRMED
    # cancelled, not because it aged out or vanished from the registry.
    assert after_second == 1
