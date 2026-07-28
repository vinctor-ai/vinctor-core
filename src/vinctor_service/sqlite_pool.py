from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from threading import RLock
from time import monotonic
from typing import Any

from vinctor_service.health_checks import resolve_readiness_timeout_seconds
from vinctor_service.idempotency_readiness import sqlite_idempotency_ready
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_pool_admission import SQLiteLeaseAdmission
from vinctor_service.sqlite_pool_context import (
    SQLiteRequestContext,
    build_sqlite_request_context,
)
from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite

DEFAULT_SQLITE_POOL_SIZE = 8
DEFAULT_SQLITE_LEASE_TIMEOUT_SECONDS = 10.0


class _ContextAttributeProxy:
    def __init__(self, pool: SQLiteServicePool, attribute: str) -> None:
        self._pool = pool
        self._attribute = attribute

    def __getattr__(self, name: str) -> Any:
        target = getattr(self._pool.current_context, self._attribute)
        return getattr(target, name)


@dataclass
class _ProbeCall:
    """One readiness call, the context it borrowed and when it started."""

    started: float
    context: SQLiteRequestContext


class SQLiteReadinessProbe:
    """The pool's readiness check, plus the cancellation hook.

    BoundedBackendProbe duck-types `cancel()` off the check it was given, and a
    bound method carries no such attribute — so wiring `pool.is_ready` directly
    left SQLite with no way to end a wedged probe at all (PKA-146). Mirrors
    PostgresReadinessProbe.
    """

    def __init__(self, pool: SQLiteServicePool, *, timeout_seconds: float | None = None) -> None:
        self._pool = pool
        self._timeout_seconds = (
            resolve_readiness_timeout_seconds() if timeout_seconds is None else timeout_seconds
        )

    def __call__(self) -> bool:
        return self._pool.is_ready()

    def cancel(self) -> None:
        self._pool.interrupt_readiness_probes(older_than=self._timeout_seconds)


class SQLiteServicePool:
    """Bounded request-scoped services over independent SQLite connections."""

    def __init__(
        self,
        database: str | Path,
        *,
        primary_connection: SerializedSQLiteConnection,
        primary_service: SQLiteV1Service,
        primary_key_repository: SQLiteLocalKeyRepository,
        size: int = DEFAULT_SQLITE_POOL_SIZE,
        connection_factory: Callable[[], SerializedSQLiteConnection] | None = None,
        lease_timeout_seconds: float = DEFAULT_SQLITE_LEASE_TIMEOUT_SECONDS,
    ) -> None:
        if size < 1:
            raise ValueError("SQLite service pool size must be at least 1")
        if lease_timeout_seconds <= 0:
            raise ValueError("SQLite service pool lease timeout must be positive")
        primary_service.assert_pool_state_contract()
        if not sqlite_idempotency_ready(
            primary_connection,
            primary_service.idempotency_keyring,
        ):
            raise RuntimeError("SQLite idempotency startup check failed")

        self._target_size = size
        self._connection_factory = connection_factory or (
            lambda: connect_sqlite(database, check_same_thread=False)
        )
        self._shared_state = primary_service.shared_state
        self._state_lock = RLock()
        self._next_generation = size + 1
        self._build_in_flight = False
        self._audit_writer = primary_service.audit_writer
        primary = SQLiteRequestContext(
            connection=primary_connection,
            service=primary_service,
            key_repository=primary_key_repository,
            generation=1,
        )
        self._contexts = [primary]
        self._available: deque[SQLiteRequestContext] = deque()
        self._admission = SQLiteLeaseAdmission(self._state_lock, self._available)
        self._lease_condition = self._admission.condition
        self._waiters = self._admission.waiters
        self._lease_timeout_seconds = lease_timeout_seconds
        self._current: ContextVar[SQLiteRequestContext | None] = ContextVar(
            f"vinctor_sqlite_request_context_{id(self)}", default=None
        )
        self._closed = False
        # Contexts readiness probes have borrowed, and the ones close() left
        # open for their probe to dispose of. Both are LISTS, not slots: the
        # bounded probe replaces a wedged worker without waiting for it, so two
        # readiness calls overlap by design and a single slot would record only
        # the newest — losing the older one's reservation and letting close()
        # shut its connection mid-statement (PKA-146). See is_ready().
        self._probe_calls: list[_ProbeCall] = []
        self._deferred_probe_contexts: list[SQLiteRequestContext] = []
        self._readiness_probe = SQLiteReadinessProbe(self)
        self.service = _ContextAttributeProxy(self, "service")
        self.key_repository = _ContextAttributeProxy(self, "key_repository")
        self._bind_ambiguity_reporter(primary)

        try:
            for generation in range(2, size + 1):
                self._contexts.append(self._build_context(generation))
        except BaseException:
            for context in self._contexts[1:]:
                context.closed = True
                context.service.close()
                context.connection.close()
            raise

        self._available.extend(self._contexts)

    @property
    def readiness_probe(self) -> SQLiteReadinessProbe:
        return self._readiness_probe

    @property
    def current_context(self) -> SQLiteRequestContext:
        context = self._current.get()
        if context is None:
            raise RuntimeError("SQLite service proxy used outside a request scope")
        return context

    @property
    def size(self) -> int:
        return self._target_size

    @property
    def capacity(self) -> int:
        with self._state_lock:
            return len(self._contexts)

    @contextmanager
    def request_scope(self) -> Iterator[None]:
        self._replenish_once()
        context = self._admission.acquire(self._lease_timeout_seconds)
        token = self._current.set(context)
        try:
            yield
        finally:
            self._current.reset(token)
            with self._state_lock:
                if (
                    not self._closed
                    and context.healthy
                    and not context.closed
                    and context in self._contexts
                ):
                    self._admission.release(context)

    def is_ready(self) -> bool:
        """Answer the traffic-readiness question for this pool.

        The pool-state half is in-memory and takes no I/O lock, and the query
        half is a local file read on a borrowed connection: there is no socket
        that can park it, so unlike PostgreSQL it needs no driver deadline.

        It is not unbounded, though. SQLite's busy timeout is 5s against a 2s
        default readiness bound, so ordinary write contention outlives the
        deadline and would spend an abandoned-worker slot on every platform.
        That is what `interrupt_readiness_probes()` is for: it is the exact
        analogue of the PostgreSQL cancel, it is safe from another thread, and
        it ends the statement rather than waiting out the busy handler.

        The borrowed connection must also survive the call: the probe runs on
        its own worker, which close() cannot always join, so closing the
        connection there would be closing it underneath a live statement.
        Borrowed contexts are reserved for the duration and whichever of close()
        and the call finishes last disposes of each one.
        """
        current = self._current.get()
        with self._state_lock:
            if self._closed or self._build_in_flight or len(self._contexts) < self._target_size:
                return False
            if current is None:
                try:
                    context = self._available.popleft()
                except IndexError:
                    return False
                self._probe_calls.append(_ProbeCall(monotonic(), context))
            else:
                context = current
                if context not in self._contexts or context.closed:
                    return False
        try:
            return (
                context.healthy
                and context.connection.execute("SELECT 1").fetchone() == (1,)
                and sqlite_idempotency_ready(
                    context.connection,
                    context.service.idempotency_keyring,
                )
            )
        except BaseException:
            return False
        finally:
            if current is None:
                self._release_probe_context(context)

    def interrupt_readiness_probes(self, *, older_than: float) -> None:
        """Abort readiness statements that have outlived the readiness bound.

        `sqlite3.Connection.interrupt()` is documented for exactly this, and the
        serialized wrapper delegates it without taking the connection lock — so
        it cannot queue behind the very statement it is trying to end.

        Two things this must not do, mirroring PostgresReadinessProbe.cancel():

        * abort a probe that has not blown the bound. Interrupting every probe
          in flight turns each reclaimer sweep into a chance of flipping a
          working /readyz to 503, since a replacement probe is in flight
          precisely when a sweep runs.
        * abort anything that is no longer a probe. `interrupt()` is
          connection-wide, so a context released back to `_available` between
          the snapshot and the call would be interrupted while an enforce
          request had it — the readiness bound reaching into the enforce path.
          Interrupting happens UNDER the state lock, which
          `_release_probe_context` also takes before releasing: not a narrower
          window, no window. Safe to hold because interrupt() only sets a flag
          and returns; the lock is still never held across I/O.
        """
        expired = monotonic() - older_than
        with self._state_lock:
            for probe in self._probe_calls:
                if probe.started > expired:
                    continue
                with suppress(Exception):
                    probe.context.connection.interrupt()

    def _release_probe_context(self, context: SQLiteRequestContext) -> None:
        with self._state_lock:
            self._probe_calls = [
                probe for probe in self._probe_calls if probe.context is not context
            ]
            deferred = context in self._deferred_probe_contexts
            if deferred:
                self._deferred_probe_contexts.remove(context)
            if (
                not self._closed
                and context.healthy
                and not context.closed
                and context in self._contexts
            ):
                self._admission.release(context)
                return
        if deferred:
            # close() skipped this one on purpose; it is ours to close now.
            context.service.close()
            context.connection.close()

    def quarantine_current_context(self, expected_generation: int) -> bool:
        context = self.current_context
        with self._state_lock:
            if (
                context.generation != expected_generation
                or not context.healthy
                or context.closed
                or context not in self._contexts
            ):
                return False
            context.healthy = False
            context.closed = True
            self._contexts.remove(context)
            if context in self._available:
                self._available.remove(context)
            self._admission.invalidate_waiters()
        context.service.close()
        context.connection.close()
        self._replenish_once()
        return True

    def complete_write_disable_barrier_with_fresh_authority(self, *, version: str) -> None:
        from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore

        connection = self._connection_factory()
        try:
            store = SQLiteIdempotencyStore(
                connection,
                keyring=self._shared_state.idempotency_keyring,
            )
            store.write_disable(version=version, reason="rotation")
        finally:
            connection.close()

    def close(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            contexts = self._contexts
            self._contexts = []
            self._admission.close()
            for context in contexts:
                context.healthy = False
                context.closed = True
            # Readiness probes may be mid-statement on the contexts they
            # borrowed, on worker threads shutdown cannot join. Closing those
            # connections here is the race PKA-146 fixes; each probe closes its
            # own when it returns. ALL of them, not just the newest: probes
            # overlap whenever a wedged worker is replaced.
            borrowed = [probe.context for probe in self._probe_calls]
            if borrowed:
                self._deferred_probe_contexts.extend(borrowed)
                contexts = [context for context in contexts if context not in borrowed]
        close_export = getattr(self._audit_writer, "close_export", None)
        if callable(close_export):
            close_export()
        for context in contexts:
            context.service.close()
            context.connection.close()

    def _build_context(self, generation: int) -> SQLiteRequestContext:
        context = build_sqlite_request_context(
            self._connection_factory,
            self._shared_state,
            generation,
        )
        self._bind_ambiguity_reporter(context)
        return context

    def _bind_ambiguity_reporter(self, context: SQLiteRequestContext) -> None:
        context.service.bind_idempotency_ambiguity_reporter(
            lambda generation=context.generation: self.quarantine_current_context(generation)
        )

    def _replenish_once(self) -> bool:
        with self._state_lock:
            if self._closed or self._build_in_flight or len(self._contexts) >= self._target_size:
                return False
            self._build_in_flight = True
            generation = self._next_generation
            self._next_generation += 1
        try:
            context = self._build_context(generation)
        except BaseException:
            with self._state_lock:
                self._build_in_flight = False
                self._admission.invalidate_waiters()
            raise
        with self._state_lock:
            self._build_in_flight = False
            if not self._closed and len(self._contexts) < self._target_size:
                self._contexts.append(context)
                self._admission.publish(context)
                return True
            context.healthy = False
            context.closed = True
        context.service.close()
        context.connection.close()
        return False
