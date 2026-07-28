from __future__ import annotations

import math
import os
import sys
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from threading import Event, Lock, Thread
from time import monotonic

from vinctor_service.v1_http import V1HttpResponse

HealthCheck = Callable[[], bool]

# A backend call that never returns parks its worker for good, so the probe
# starts a replacement and abandons the old one. Abandoned workers are capped:
# a store that never answers again must not cost one thread — and one driver
# session — per readiness probe for the life of the process. At the cap
# readiness fails closed and reports it once on stderr.
#
# The cap is only tolerable because it is temporary. Reaching it starts, and
# keeps, the reclaimer cancelling the wedged calls; cancelling reaches the store
# over a new connection, so the slots come back as soon as the store does. A cap
# that could only be cleared by the store answering a call it had already
# swallowed would be this card's own defect with a bigger budget.
MAX_ABANDONED_READINESS_WORKERS = 4

# How long /readyz will wait for the durable store before answering
# "unavailable". The bound has to be explicit: a hung backend socket has no
# timeout of its own, so without this a readiness probe blocks for as long as
# the outage lasts. Kept below the 5s probe timeouts in the shipped Compose
# healthchecks and below HANDLER_TIMEOUT_SECONDS so the answer arrives before
# the caller or the handler gives up.
#
# It is a default, not a constant, because the probe is not free: it runs the
# idempotency-readiness queries as well as SELECT 1. A busy-but-healthy store
# can exceed 2s, and reporting that as "unavailable" drains the busiest instance
# and shifts its load onto its peers. Operators raise it with
# VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS. On Postgres it is also the driver and
# server side bound on the probe's own connection (PKA-146), so raising it
# raises how long a single probe may hold that session.
READINESS_PROBE_TIMEOUT_SECONDS = 2.0


def resolve_readiness_timeout_seconds() -> float:
    """Parse VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS once per probe.

    Unset, unparseable, non-positive, NaN, or infinite -> the default. Infinity
    is rejected rather than honoured: an unbounded readiness probe is the bug
    this bound exists to prevent, so no configuration may switch it off.
    """
    raw = os.environ.get("VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS")
    if raw is None:
        return READINESS_PROBE_TIMEOUT_SECONDS
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return READINESS_PROBE_TIMEOUT_SECONDS
    if not math.isfinite(value) or value <= 0:
        return READINESS_PROBE_TIMEOUT_SECONDS
    return value


def _write_report(report: str | None) -> None:
    """Emit an operator line without ever waiting for it.

    Not under the probe lock, and not on the caller's path either: stderr can
    block — a stalled log collector is enough — and /readyz must answer at its
    own bound whatever the log pipeline is doing. The line is advisory, so it is
    dispatched and forgotten rather than waited on. Once per episode, so this
    does not spawn threads at request rate.
    """
    if report is None:
        return

    def write() -> None:
        with suppress(Exception):
            sys.stderr.write(report)

    with suppress(RuntimeError):
        Thread(target=write, name="vinctor-readiness-report", daemon=True).start()


def health_response(
    method: str,
    service_mode: str,
) -> V1HttpResponse:
    """Answer process liveness. Performs no I/O of any kind (PKA-117).

    Liveness answers "can this process serve at all", not "is the durable store
    usable" — that is /readyz. Running a store probe here made a Postgres
    outage restart every pod at once.
    """
    if method != "GET":
        return V1HttpResponse(
            status_code=405,
            body={
                "error": "method_not_allowed",
                "reason": "GET is required for /healthz",
            },
        )
    return V1HttpResponse(
        status_code=200,
        body={
            "status": "ok",
            "service": "vinctor-service",
            "mode": service_mode,
        },
    )


def readiness_response(
    method: str,
    readiness_check: HealthCheck,
) -> V1HttpResponse:
    if method != "GET":
        return V1HttpResponse(
            status_code=405,
            body={
                "error": "method_not_allowed",
                "reason": "GET is required for /readyz",
            },
        )
    try:
        ready = readiness_check()
    except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK - coarse HTTP boundary
        ready = False
    return V1HttpResponse(
        status_code=200 if ready else 503,
        body={
            "status": "ready" if ready else "unavailable",
            "service": "vinctor-service",
        },
    )


@dataclass
class _Probe:
    deadline: float
    finished: Event = field(default_factory=Event)
    ready: bool = False


@dataclass
class _Worker:
    """One probe worker thread and the handoff it parks on.

    ``idle`` marks the only state in which the worker can pick up a new probe:
    parked on ``requested``, or on its way there through statements that cannot
    block. Liveness is NOT that state — a worker blocked inside the backend call
    is alive and never returns to the handoff, so gating on ``is_alive()`` left
    every later probe waiting on a request nobody would ever service (PKA-146).
    Only the worker can report this, so only the worker sets ``idle``.
    """

    requested: Event = field(default_factory=Event)
    idle: Event = field(default_factory=Event)
    thread: Thread | None = None
    abandoned: bool = False
    counted: bool = False


class BoundedBackendProbe:
    """Run a durable-store readiness check under an explicit deadline.

    The check runs on a persistent daemon worker instead of the request thread,
    so a hung backend socket cannot hold /readyz open past the bound. Three
    properties matter and each is load-bearing:

    * bounded — a caller waits no longer than its probe's deadline and fails
      closed at it;
    * single-flight — while one check is outstanding no second one starts, so
      an unauthenticated probe flood cannot amplify a *saturated* backend into
      one query per request. (Against a healthy backend the flood still costs
      one round-trip per request: there is no result cache and no minimum
      inter-probe interval. Single-flight bounds concurrency, not query rate.)
    * self-healing — no transient failure may latch /readyz at 503. A probe is
      replaced once it finishes *or* once its deadline passes, and a failed
      `Thread.start()` records no worker, so thread exhaustion or a dead worker
      costs one failed probe rather than permanent removal from rotation.
      Replacing the probe object is not enough on its own: there also has to be
      a worker that can RUN it. A worker blocked inside the backend call is
      alive but will never come back to the handoff, so the probe tracks
      availability (parked on the handoff) rather than liveness and starts a
      replacement, abandoning the blocked one (PKA-146). Turning a transient
      fault into permanent availability loss is the same amplification PKA-117
      removed from the liveness path; it must not reappear on readiness.

    Abandoning is capped at `max_abandoned_workers` and the cap is observable
    (`abandoned_workers`, `abandoned_worker_limit_hits`, one stderr line per
    episode), so a permanently wedged store fails readiness closed instead of
    spawning threads without limit or failing quietly.

    The cap is only safe because it cannot absorb. A healthy backend must yield
    a 200 within a bounded time however many earlier calls are wedged, and that
    must not depend on a wedged call returning of its own accord. So while any
    worker is abandoned a dedicated reclaimer thread calls the check's
    `cancel()` and keeps calling it: cancelling reaches the backend over a NEW
    connection, so the moment the store is reachable again the wedged calls are
    aborted, their slots come back, and the next probe answers. Reclamation runs
    on that thread and nowhere else — never on a caller's thread and never on a
    replacement worker's — because it is I/O, and anything on those paths is
    spending a readiness deadline.

    Every give-up path returns False — readiness fails closed.
    """

    def __init__(
        self,
        check: HealthCheck,
        *,
        timeout_seconds: float | None = None,
        max_abandoned_workers: int = MAX_ABANDONED_READINESS_WORKERS,
    ) -> None:
        self._check = check
        self._timeout_seconds = (
            resolve_readiness_timeout_seconds() if timeout_seconds is None else timeout_seconds
        )
        self._max_abandoned_workers = max_abandoned_workers
        self._lock = Lock()
        self._probe: _Probe | None = None
        self._worker: _Worker | None = None
        self._abandoned = 0
        self._abandoned_limit_hits = 0
        self._limit_reported = False
        self._closed = False
        self._reclaim = Event()
        self._stopped = Event()
        self._reclaimer: Thread | None = None
        self._pending_report: str | None = None
        # Duck-typed like the connection hooks in service_runtime: a check that
        # owns a backend handle offers cancel(), and a backend with nothing to
        # cancel (SQLite reads a local file) needs no wiring.
        cancel = getattr(check, "cancel", None)
        self._cancel: Callable[[], None] | None = cancel if callable(cancel) else None

    @property
    def abandoned_workers(self) -> int:
        """Workers currently abandoned inside a backend call that has not returned."""
        with self._lock:
            return self._abandoned

    @property
    def abandoned_worker_limit_hits(self) -> int:
        """Probes that failed closed because the abandoned-worker cap was reached."""
        with self._lock:
            return self._abandoned_limit_hits

    def __call__(self) -> bool:
        report: str | None = None
        with self._lock:
            if self._closed:
                return False
            now = monotonic()
            probe = self._probe
            # An expired probe is replaced as well as a finished one. Reusing an
            # expired-but-unfinished probe would make a dead worker permanent:
            # nobody would ever finish it and no later call would restart the
            # worker.
            if probe is None or probe.finished.is_set() or probe.deadline <= now:
                worker = self._servicing_worker()
                report = self._pending_report
                self._pending_report = None
                if worker is None:
                    # No worker could run this probe. Fail closed now and leave
                    # no probe behind, so the next call retries from a clean
                    # state.
                    _write_report(report)
                    return False
                probe = _Probe(deadline=now + self._timeout_seconds)
                self._probe = probe
                worker.requested.set()
        _write_report(report)
        remaining = probe.deadline - monotonic()
        # wait(0) still reports a probe that completed in the meantime; anything
        # unfinished at its deadline is reported unavailable.
        if not probe.finished.wait(remaining if remaining > 0 else 0):
            return False
        return probe.ready

    def close(self) -> None:
        """Stop and join the worker.

        Called from server_close(), which both runtime handles run before they
        close the backend connection. A worker still blocked on a wedged backend
        is left as a daemon thread rather than blocking shutdown: refusing to
        exit because the store is hung is the failure mode this whole change
        removes. Because the join can therefore time out, the check owns the
        resources it touches — nothing shared may be closed underneath a worker
        this call could not stop (PKA-146).
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
            worker = self._worker
            self._worker = None
            reclaimer = self._reclaimer
            self._reclaimer = None
        self._stopped.set()
        self._reclaim.set()
        if worker is not None:
            worker.abandoned = True
            worker.requested.set()
        # Cancelling is bounded here too: shutdown must not hang on a cancel the
        # driver never returns from.
        self._cancel_backend_call()
        if worker is not None and worker.thread is not None:
            worker.thread.join(timeout=self._timeout_seconds)
        if reclaimer is not None:
            reclaimer.join(timeout=self._timeout_seconds)

    def _servicing_worker(self) -> _Worker | None:
        """Return a worker that can run the next probe. Caller holds the lock."""
        worker = self._worker
        if worker is None:
            return self._start_worker()
        if worker.idle.is_set():
            return worker
        alive = worker.thread is not None and worker.thread.is_alive()
        if alive and self._abandoned >= self._max_abandoned_workers:
            # The store has swallowed every worker we are willing to spend. Keep
            # the current one recorded, and keep the reclaimer running: this
            # state ends when a wedged call is cancelled, which needs only the
            # store to become reachable again — not for it to answer the call it
            # already swallowed.
            self._abandoned_limit_hits += 1
            self._pending_report = self._report_limit()
            self._wake_reclaimer()
            return None
        self._worker = None
        worker.abandoned = True
        # Wake it, so a worker that merely lost the race to park exits instead
        # of holding a slot until the process does.
        worker.requested.set()
        if alive:
            self._abandoned += 1
            worker.counted = True
            # Before starting the replacement, and independent of whether that
            # start succeeds: reclaiming this call must not hinge on there being
            # a replacement worker to do it (nor happen on that worker's time).
            self._wake_reclaimer()
        # A worker whose thread is already gone — a BaseException escape — costs
        # no slot and has no backend call left to cancel.
        return self._start_worker()

    def _start_worker(self) -> _Worker | None:
        """Start a fresh worker. Caller holds the lock."""
        worker = _Worker()
        thread = Thread(
            target=self._serve,
            args=(worker,),
            name="vinctor-readiness-probe",
            daemon=True,
        )
        worker.thread = thread
        try:
            thread.start()
        except RuntimeError:
            # Thread exhaustion, or an interpreter that is shutting down. Record
            # nothing: a failed start must leave the probe restartable.
            return None
        self._worker = worker
        self._limit_reported = False
        return worker

    def _release_worker(self, worker: _Worker) -> None:
        with self._lock:
            if worker.counted:
                worker.counted = False
                self._abandoned -= 1
                # A freed slot ends the episode, so a later one is reported
                # again rather than swallowed by the first one's flag.
                self._limit_reported = False
            if self._worker is worker:
                self._worker = None

    def _wake_reclaimer(self) -> None:
        """Ensure the reclaimer is running and awake. Caller holds the lock.

        Liveness is the right question HERE, unlike for the probe worker. The
        worker runs the check, which blocks for as long as the store does — so
        it is tracked by availability. This loop's only waits are the handoff,
        which this call sets, and two bounded ones: the retry delay, and a
        cancel the driver is required to bound (the Postgres backend refuses to
        start below libpq 17, and the SQLite cancel is a non-blocking
        interrupt()). A reclaimer that is alive is therefore always one that is
        working, and the stall/supersede machinery that assumed otherwise is
        gone with the condition that motivated it.
        """
        if self._cancel is None or self._closed:
            return
        self._reclaim.set()
        reclaimer = self._reclaimer
        if reclaimer is not None and reclaimer.is_alive():
            return
        reclaimer = Thread(
            target=self._reclaim_loop,
            name="vinctor-readiness-reclaimer",
            daemon=True,
        )
        try:
            reclaimer.start()
        except RuntimeError:
            # Out of threads. The next abandonment retries; nothing is recorded,
            # exactly as for a worker that could not start.
            return
        self._reclaimer = reclaimer

    def _reclaim_loop(self) -> None:
        """Cancel abandoned backend calls until they are gone.

        Repeats rather than firing once: a cancel travels over a new connection,
        so while the store is unreachable it cannot be delivered, and the only
        thing that ends that is the store coming back. Retrying is what turns
        the abandoned-worker cap from an absorbing state into a temporary one.
        """
        while not self._stopped.is_set():
            self._reclaim.wait()
            if self._stopped.is_set():
                return
            with self._lock:
                if self._abandoned == 0:
                    # Any abandonment after this check sets the event again, so
                    # clearing it here cannot lose a wake-up.
                    self._reclaim.clear()
                    continue
            self._cancel_backend_call()
            self._stopped.wait(self._timeout_seconds)

    def _report_limit(self) -> str | None:
        """Decide whether to report the cap. Caller holds the lock.

        Returns the line rather than writing it: stderr can block — a stalled
        log collector is enough — and this lock is the one /readyz takes on
        every request. Writing here made the endpoint wait on the log pipeline,
        with no bound of its own. The same delegated-bound mistake as the rest
        of this card, in the one place it is least expected.
        """
        if self._limit_reported:
            return None
        self._limit_reported = True
        return (
            f"vinctor: readiness probe is holding {self._abandoned} abandoned worker(s) "
            "on a backend call that has not returned; readiness fails closed until one "
            "of them does\n"
        )

    def _cancel_backend_call(self) -> None:
        """Cancel the abandoned backend calls.

        Runs on the reclaimer, and on the closing thread from close() — never on
        a request thread. No deadline of its own and no thread to enforce one:
        the cancel is required to be bounded by the driver (a bounded
        cancel_safe on Postgres, a non-blocking interrupt() on SQLite), and
        neither caller is inside a readiness deadline. Wrapping it in a bound
        here would be machinery for a condition the requirement removes.

        It does lengthen shutdown, which is where that bound also used to
        apply: worst case is now about 14s (a ~5s serial cancel sweep, a 2s
        worker join, a 2s reclaimer join, and up to 5s more in
        PostgresReadinessProbe.close()'s own sweep) against roughly 9s before.
        Bounded, and inside the 30s grace period a terminating pod gets by
        default.
        """
        cancel = self._cancel
        if cancel is None:
            return
        with suppress(Exception):
            # Silent by design: a cancel that cannot be delivered is the normal
            # state during an outage, and the abandoned-worker report already
            # tells an operator that calls are stuck.
            cancel()

    def _serve(self, worker: _Worker) -> None:
        try:
            while True:
                worker.idle.set()
                worker.requested.wait()
                # Cleared before the probe is read, so a request that arrives
                # while this worker is waking is picked up by the read below
                # rather than lost.
                worker.requested.clear()
                worker.idle.clear()
                with self._lock:
                    if self._closed or worker.abandoned:
                        return
                    probe = self._probe
                if probe is None or probe.finished.is_set():
                    continue
                ready = False
                try:
                    ready = bool(self._check())
                except Exception:  # coarse boundary; readiness fails closed
                    ready = False
                finally:
                    # In `finally` so that no escape — including a BaseException
                    # that kills this thread — can leave a caller waiting on a probe
                    # nobody will ever complete. A dead worker is replaced by the
                    # next call; an unfinished probe would not be.
                    #
                    # `idle` is set before `finished` so the caller this probe
                    # releases cannot mistake the gap between finishing and
                    # parking again for a stalled worker: everything between
                    # here and requested.wait() runs without blocking, and the
                    # Event is level-triggered, so a request set in that window
                    # is still served.
                    worker.idle.set()
                    probe.ready = ready
                    probe.finished.set()
        finally:
            self._release_worker(worker)
