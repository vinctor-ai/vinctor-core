"""PKA-117: process liveness must not depend on the durable store.

`/healthz` used to run the Postgres durable-store probe while the deployment
guidance told operators to wire `/healthz` to the Kubernetes *liveness* probe.
A Postgres outage therefore failed liveness on every pod at once, restarting
the whole fleet under exactly the condition an operator needs the fleet alive
to diagnose.

These tests pin the separation with a hung, a disconnected, and a saturated
durable store. All three are faked, so they run in the default suite without a
live PostgreSQL (see tests/test_postgres_recovery_live.py for the live case).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
from http.client import HTTPConnection
from pathlib import Path
from threading import Event, Lock, Thread
from threading import enumerate as enumerate_threads
from time import monotonic, sleep
from typing import Any

import pytest
import yaml

from vinctor_service import health_checks
from vinctor_service.health_checks import (
    READINESS_PROBE_TIMEOUT_SECONDS,
    BoundedBackendProbe,
    resolve_readiness_timeout_seconds,
)
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import ServiceRuntimeHandle, prepare_service_runtime

ROOT = Path(__file__).resolve().parents[1]
DSN = "postgresql://vinctor:top-secret@db/vinctor"


class _StoreUnavailable(RuntimeError):
    pass


class _Rows:
    def fetchone(self) -> tuple[int]:
        return (1,)

    def fetchall(self) -> list[Any]:
        return []


class _DurableStore:
    """Stand-in for the PostgreSQL handles the runtime owns.

    Stands in for both the process connection and the connection the readiness
    probe opens for itself, so one fake can answer "did anything touch the
    store". Every durable-store probe goes through ``transaction()``; ``probes``
    counts them, so a route that never touches the store is provable rather than
    asserted by reading the code.
    """

    def __init__(self, *, hang: bool = False, error: str | None = None) -> None:
        self.probes = 0
        self.max_concurrent_probes = 0
        self.cancels = 0
        self._hang = hang
        self._error = error
        self._concurrent = 0
        self._lock = Lock()
        self._released = Event()

    def execute(self, *args: Any, **kwargs: Any) -> _Rows:
        return _Rows()

    def cancel(self) -> None:
        # Counted, not honoured: a cancel that always unblocks the backend would
        # hide the case these tests exist for.
        with self._lock:
            self.cancels += 1

    def transaction(self) -> Any:
        with self._lock:
            self.probes += 1
            self._concurrent += 1
            self.max_concurrent_probes = max(self.max_concurrent_probes, self._concurrent)
        try:
            if self._hang:
                # A hung socket: the probe returns only when the backend does.
                # Bounded by the test's release() so no thread lingers.
                self._released.wait(timeout=30)
            if self._error is not None:
                raise _StoreUnavailable(self._error)
            return nullcontext()
        finally:
            with self._lock:
                self._concurrent -= 1

    def release(self) -> None:
        self._released.set()

    def close(self) -> None:
        return None


class _FakeService:
    def close(self) -> None:
        return None


class _FakeKeys:
    pass


def _fake_postgres(store: _DurableStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "vinctor_service.service_runtime.connect_postgres",
        lambda dsn: store,
    )
    # The readiness probe opens a connection of its own (PKA-146). Faking it too
    # keeps these tests off the network and keeps `probes` counting every probe.
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


@contextmanager
def _postgres_runtime(
    store: _DurableStore,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[ServiceRuntimeHandle]:
    _fake_postgres(store, monkeypatch)
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


def test_healthz_runs_no_durable_store_probe(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given a PostgreSQL runtime whose durable store is hung.
    store = _DurableStore(hang=True)

    # When liveness is probed repeatedly.
    with _postgres_runtime(store, monkeypatch) as handle:
        started = monotonic()
        results = [_get(handle, "/healthz") for _ in range(5)]
        elapsed = monotonic() - started

    # Then every probe answers "alive" and the store was never touched.
    assert [status for status, _, _ in results] == [200, 200, 200, 200, 200]
    assert all(body["status"] == "ok" for _, body, _ in results)
    assert store.probes == 0
    assert elapsed < READINESS_PROBE_TIMEOUT_SECONDS


def test_hung_store_fails_readiness_within_the_bound_without_failing_liveness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a PostgreSQL runtime whose durable store never answers a probe.
    store = _DurableStore(hang=True)

    with _postgres_runtime(store, monkeypatch) as handle, ThreadPoolExecutor(2) as executor:
        # When readiness is probed and liveness is probed while it hangs.
        started = monotonic()
        readiness = executor.submit(_get, handle, "/readyz")
        sleep(0.1)
        liveness_started = monotonic()
        liveness_status, liveness_body, _ = _get(handle, "/healthz")
        liveness_elapsed = monotonic() - liveness_started
        readiness_status, readiness_body, readiness_raw = readiness.result(timeout=20)
        readiness_elapsed = monotonic() - started
        # Captured before teardown releases the store: afterwards the probe
        # completes and goes on to check the serving connection, which is the
        # same fake here.
        probes_while_hung = store.probes

    # Then liveness answers immediately while readiness is still blocked...
    assert liveness_status == 200
    assert liveness_body["status"] == "ok"
    assert liveness_elapsed < 1.0
    # ...and readiness gives up at the bound instead of hanging with the socket.
    assert readiness_status == 503
    assert readiness_body == {"status": "unavailable", "service": "vinctor-service"}
    assert readiness_elapsed < READINESS_PROBE_TIMEOUT_SECONDS + 3.0
    assert probes_while_hung == 1
    # No-disclosure: the bound must not turn into a backend-identity side channel.
    assert "postgresql://" not in readiness_raw
    assert "top-secret" not in readiness_raw
    assert "timeout" not in readiness_raw.lower()


def test_disconnected_store_fails_readiness_coarsely_without_failing_liveness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a durable store that refuses connections and names the DSN when it does.
    store = _DurableStore(error=f"{DSN} connection refused")

    with _postgres_runtime(store, monkeypatch) as handle:
        # When both probes run.
        readiness_status, readiness_body, readiness_raw = _get(handle, "/readyz")
        liveness_status, liveness_body, _ = _get(handle, "/healthz")

    # Then only readiness fails, and it discloses nothing about the backend.
    assert liveness_status == 200
    assert liveness_body["status"] == "ok"
    assert readiness_status == 503
    assert readiness_body == {"status": "unavailable", "service": "vinctor-service"}
    assert "postgresql://" not in readiness_raw
    assert "top-secret" not in readiness_raw
    assert "connection refused" not in readiness_raw
    assert store.probes == 1


def test_saturated_store_is_not_amplified_by_probe_traffic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a saturated store: every probe queues behind the backend and blocks
    # past the readiness bound.
    store = _DurableStore(hang=True)

    with _postgres_runtime(store, monkeypatch) as handle, ThreadPoolExecutor(16) as executor:
        # When a burst of readiness and liveness probes arrives at once.
        readiness = [executor.submit(_get, handle, "/readyz") for _ in range(8)]
        liveness = [executor.submit(_get, handle, "/healthz") for _ in range(8)]
        readiness_statuses = [future.result(timeout=20)[0] for future in readiness]
        liveness_statuses = [future.result(timeout=20)[0] for future in liveness]

    # Then liveness never fails, readiness fails closed, and the saturated store
    # sees at most one outstanding probe no matter how many probes arrive.
    assert liveness_statuses == [200] * 8
    assert readiness_statuses == [503] * 8
    assert store.max_concurrent_probes == 1


def _fenced_yaml_blocks(markdown: str) -> list[str]:
    blocks: list[str] = []
    collecting: list[str] | None = None
    for line in markdown.splitlines():
        if line.strip() == "```yaml":
            collecting = []
            continue
        if collecting is not None and line.strip() == "```":
            blocks.append("\n".join(collecting))
            collecting = None
            continue
        if collecting is not None:
            collecting.append(line)
    return blocks


def test_documented_kubernetes_probes_map_liveness_to_healthz() -> None:
    # The card's root cause was the deployment guidance, not only the code: it
    # told operators to put /healthz on the liveness probe while /healthz ran a
    # database query. This pins the shipped documentation example, so unlike the
    # tests above it would still pass against reverted code — its job is to stop
    # the guidance half of the bug from coming back, not the code half.
    topology = ROOT / "docs" / "deployment" / "production-topology.md"
    examples = [
        yaml.safe_load(block)
        for block in _fenced_yaml_blocks(topology.read_text(encoding="utf-8"))
        if "livenessProbe" in block
    ]

    assert examples, "the topology doc must ship a probe example"
    for example in examples:
        assert example["livenessProbe"]["httpGet"]["path"] == "/healthz"
        assert example["readinessProbe"]["httpGet"]["path"] == "/readyz"


@pytest.mark.parametrize(
    "compose_path",
    ["compose.yaml", "deploy/preview/compose.yaml", "deploy/reference/compose.yaml"],
)
def test_compose_healthchecks_gate_on_readiness_not_liveness(compose_path: str) -> None:
    # A container healthcheck is a traffic/dependency gate, so it must probe
    # /readyz. Probing /healthz would gate on a signal that no longer moves.
    compose = yaml.safe_load((ROOT / compose_path).read_text(encoding="utf-8"))
    probe = " ".join(compose["services"]["vinctor"]["healthcheck"]["test"])

    assert "/readyz" in probe
    assert "/healthz" not in probe


def test_runtime_close_stops_the_readiness_worker_before_closing_the_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a runtime whose store records which readiness workers are still
    # running at the moment the durable connection is closed.
    baseline = _readiness_workers()
    alive_at_close: list[set[Thread]] = []

    class _RecordingStore(_DurableStore):
        def close(self) -> None:
            alive_at_close.append(_readiness_workers() - baseline)

    store = _RecordingStore()
    _fake_postgres(store, monkeypatch)
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
        _get(handle, "/readyz")
        assert len(_readiness_workers() - baseline) == 1
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()

    # Then the worker was already stopped when the connections it probes were
    # closed — an unsynchronized concurrent close on a live connection is
    # exactly what the serialized-connection lock cannot protect against — and
    # nothing is left running afterwards. Two records: the probe's own
    # connection is closed as well as the runtime's (PKA-146), and this one fake
    # stands in for both.
    assert alive_at_close == [set(), set()]
    assert _readiness_workers() - baseline == set()


def _dockerfile_healthcheck(dockerfile: str) -> str:
    directive: list[str] = []
    for line in dockerfile.splitlines():
        if directive or line.startswith("HEALTHCHECK"):
            directive.append(line.strip())
        if directive and not directive[-1].endswith("\\"):
            break
    return " ".join(part.rstrip("\\").strip() for part in directive)


def test_published_image_healthcheck_gates_on_readiness_not_liveness() -> None:
    # The image HEALTHCHECK is the default gate for `docker run`, Swarm, ECS,
    # Nomad, and any compose file without its own healthcheck: block. Pointing
    # it at /healthz would report "healthy" through a total store outage —
    # exactly the failure this change warns operators about, shipped in our own
    # artifact. The three compose files are covered above; this covers the image.
    healthcheck = _dockerfile_healthcheck((ROOT / "Dockerfile").read_text(encoding="utf-8"))

    assert healthcheck, "the image must define a HEALTHCHECK"
    assert "/readyz" in healthcheck
    assert "/healthz" not in healthcheck


def test_bounded_probe_gives_up_at_the_deadline() -> None:
    # Given a backend check that never returns.
    release = Event()

    def hangs() -> bool:
        release.wait(timeout=30)
        return True

    probe = BoundedBackendProbe(hangs, timeout_seconds=0.2)
    started = monotonic()
    try:
        # When the probe is called.
        result = probe()
        elapsed = monotonic() - started
    finally:
        release.set()

    # Then it fails closed at the bound rather than waiting for the backend.
    assert result is False
    assert elapsed < 2.0


def test_bounded_probe_fails_closed_when_the_check_raises() -> None:
    def fails() -> bool:
        raise _StoreUnavailable("postgresql://vinctor:top-secret@db/vinctor is down")

    assert BoundedBackendProbe(fails, timeout_seconds=1.0)() is False


@pytest.mark.parametrize("answer", [True, False])
def test_bounded_probe_returns_the_backend_answer(answer: bool) -> None:
    calls: list[int] = []

    def check() -> bool:
        calls.append(1)
        return answer

    assert BoundedBackendProbe(check, timeout_seconds=1.0)() is answer
    # Without this the `False` case would also pass on a timeout, on a raised
    # check, and on a worker that never started: it must distinguish "the
    # backend said no" from "we failed closed without ever asking".
    assert calls == [1]


def _poll_until_ready(probe: BoundedBackendProbe, timeout: float = 5.0) -> bool:
    deadline = monotonic() + timeout
    while monotonic() < deadline:
        if probe():
            return True
        sleep(0.05)
    return False


def _readiness_workers() -> set[Thread]:
    return {
        thread
        for thread in enumerate_threads()
        if thread.name == "vinctor-readiness-probe" and thread.is_alive()
    }


def test_probe_recovers_when_the_worker_thread_cannot_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a machine that is briefly out of threads.
    starts: list[int] = []
    real_thread = health_checks.Thread

    class _FlakyThread(real_thread):  # type: ignore[misc, valid-type]
        def start(self) -> None:
            starts.append(1)
            if len(starts) == 1:
                raise RuntimeError("can't start new thread")
            super().start()

    monkeypatch.setattr(health_checks, "Thread", _FlakyThread)
    probe = BoundedBackendProbe(lambda: True, timeout_seconds=0.5)

    # When the first probe cannot start its worker, and the machine recovers.
    first = probe()
    recovered = _poll_until_ready(probe)
    probe.close()

    # Then readiness fails closed once and then comes back on its own. A failed
    # start must not latch /readyz at 503 for the process lifetime: that would
    # drain the pod from rotation permanently — the same amplification this
    # card exists to remove, moved from liveness to readiness.
    assert first is False
    assert recovered is True


# The escape is the point of the test: it genuinely kills the worker thread, so
# pytest's unhandled-thread-exception warning is expected output, not a defect.
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_probe_recovers_when_the_check_escapes_as_a_base_exception() -> None:
    # Given a check whose first call escapes as a BaseException, which `except
    # Exception` does not catch and which kills the worker thread.
    calls: list[int] = []

    def check() -> bool:
        calls.append(1)
        if len(calls) == 1:
            raise KeyboardInterrupt("simulated interpreter-level escape")
        return True

    probe = BoundedBackendProbe(check, timeout_seconds=2.0)

    # When the escaping probe is called, then later ones.
    started = monotonic()
    first = probe()
    first_elapsed = monotonic() - started
    recovered = _poll_until_ready(probe)
    probe.close()

    # Then the escape still finishes its probe, so the caller is answered at
    # once rather than blocking for the whole bound on a probe nobody will ever
    # complete...
    assert first is False
    assert first_elapsed < 1.0
    # ...and the dead worker is replaced instead of wedging /readyz at 503.
    assert recovered is True
    assert len(calls) >= 2


def test_probe_close_stops_and_joins_the_worker() -> None:
    # Given a probe that has served a request, so its worker exists.
    before = _readiness_workers()
    probe = BoundedBackendProbe(lambda: True, timeout_seconds=0.5)
    assert probe() is True
    assert len(_readiness_workers() - before) == 1

    # When the probe is closed.
    probe.close()

    # Then the worker is stopped and joined, not leaked for the process
    # lifetime holding the backend connection it probes.
    assert _readiness_workers() - before == set()
    assert probe() is False


def test_readiness_bound_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given an operator who raised the bound because their store is slow but healthy.
    monkeypatch.setenv("VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS", "0.25")
    release = Event()

    def hangs() -> bool:
        release.wait(timeout=30)
        return True

    probe = BoundedBackendProbe(hangs)
    started = monotonic()
    try:
        # When a probe runs against a store that never answers.
        result = probe()
        elapsed = monotonic() - started
    finally:
        release.set()
        probe.close()

    # Then the configured bound is used, not the hard-coded default.
    assert result is False
    assert 0.2 <= elapsed < READINESS_PROBE_TIMEOUT_SECONDS


@pytest.mark.parametrize("raw", ["0", "-1", "abc", "", "inf", "nan", "1e400"])
def test_invalid_readiness_bound_falls_back_to_the_default(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # An unbounded or nonsensical bound would defeat the point, so every
    # rejected value lands on the default rather than on "no deadline".
    monkeypatch.setenv("VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS", raw)

    assert resolve_readiness_timeout_seconds() == READINESS_PROBE_TIMEOUT_SECONDS


def test_bounded_probe_recovers_after_the_backend_returns() -> None:
    # Given a backend that hangs for the first probe and then answers.
    release = Event()
    calls: list[int] = []

    def check() -> bool:
        calls.append(1)
        if len(calls) == 1:
            release.wait(timeout=30)
        return True

    probe = BoundedBackendProbe(check, timeout_seconds=0.2)

    # When the first probe times out, the backend recovers, and a later probe runs.
    assert probe() is False
    release.set()
    deadline = monotonic() + 5.0
    while monotonic() < deadline and probe() is False:
        sleep(0.05)

    # Then readiness returns without needing a restart.
    assert probe() is True


class _TrackingProbeTarget:
    """Records how many checks run concurrently."""

    def __init__(self, release: Event) -> None:
        self.max_concurrent = 0
        self._concurrent = 0
        self._lock = Lock()
        self._release = release

    def __call__(self) -> bool:
        with self._lock:
            self._concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self._concurrent)
        try:
            self._release.wait(timeout=30)
            return True
        finally:
            with self._lock:
                self._concurrent -= 1


def test_bounded_probe_is_single_flight() -> None:
    # Given a slow backend check and many concurrent callers.
    release = Event()
    target = _TrackingProbeTarget(release)
    probe = BoundedBackendProbe(target, timeout_seconds=0.2)

    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [executor.submit(probe) for _ in range(8)]
            results = [future.result(timeout=20) for future in futures]
    finally:
        release.set()

    # Then a probe flood produces at most one outstanding backend check.
    assert results == [False] * 8
    assert target.max_concurrent == 1
