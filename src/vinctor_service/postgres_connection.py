from __future__ import annotations

import math
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from functools import partial
from typing import Any, Final

from vinctor_service.idempotency_models import AmbiguousCommitError
from vinctor_service.postgres_driver import PostgresDriverUnavailable
from vinctor_service.postgres_recovery_connection import (
    one_shot_authoritative_recovery,
    validate_replacement_candidate,
)

_RECONNECT_BACKOFF_SECONDS: Final = (0.05, 0.1)

# psycopg's Connection.cancel_safe() accepts a timeout but honours it only from
# libpq 17; below that it silently discards it and falls back to PQcancel, a
# blocking connect/send/recv with no timeout at all. Readiness reclaims a wedged
# probe by cancelling it, so a cancel that can hang forever means the
# abandoned-worker cap can never drain and /readyz stays unavailable after the
# database has recovered (PKA-146). That is a requirement, not a preference: the
# backend refuses to start below it rather than carrying bookkeeping to survive
# a cancel that may never return.
MINIMUM_LIBPQ_VERSION: Final = 170000


def format_libpq_version(version: int) -> str:
    if version >= 100000:
        return f"{version // 10000}.{version % 10000}"
    return f"{version // 10000}.{version % 10000 // 100}.{version % 100}"


def require_supported_libpq() -> None:
    """Refuse the Postgres backend unless a bounded cancellation is available.

    The property everything here rests on is `Connection.cancel_safe(timeout=)`,
    and that needs TWO things: libpq 17+ (below it psycopg silently discards the
    timeout and falls back to a blocking PQcancel) and psycopg 3.2+, which is
    where the method was introduced at all. Checking the libpq version alone
    passes on psycopg 3.1 against libpq 18 — the method is simply absent, every
    cancel raises AttributeError into a `return False`, and the abandoned-worker
    cap never drains: PKA-146 again, silently. The `postgres` extra pins psycopg
    3.2+, but an operator's own resolver is not something this adapter may rely
    on.

    `capabilities.has_cancel_safe(check=True)` is psycopg's own answer to
    exactly this question and covers both halves, so it is the check rather than
    a version number standing in for one.

    Called from the backend's own initialisation path, where psycopg is already
    known to be importable — never at module scope, so a default install with no
    `[postgres]` extra is unaffected.
    """
    import psycopg

    detected = f"libpq {format_libpq_version(psycopg.pq.version())}"
    with suppress(Exception):
        detected = f"psycopg {psycopg.__version__}, {detected}"
    remedy = (
        "Without it a readiness probe that wedges can never be reclaimed and "
        "/readyz stays unavailable after the database recovers. Install "
        "`vinctor-core[postgres]`, which pins psycopg 3.2+ with a bundled "
        "libpq, or provide psycopg 3.2+ built against libpq 17 or newer."
    )
    capabilities = getattr(psycopg, "capabilities", None)
    has_cancel_safe = getattr(capabilities, "has_cancel_safe", None)
    if has_cancel_safe is None:
        # psycopg < 3.2: no capabilities object, and no cancel_safe either.
        raise RuntimeError(  # noqa: TRY003  # noqa: GENERIC_ERR_OK - startup refusal
            "PostgreSQL support requires psycopg 3.2 or newer, which is where "
            f"Connection.cancel_safe() was introduced; detected {detected}. "
            + remedy
        )
    try:
        has_cancel_safe(check=True)
    except Exception as exc:
        raise RuntimeError(  # noqa: TRY003  # noqa: GENERIC_ERR_OK - startup refusal
            "PostgreSQL support requires a bounded query cancellation "
            f"(Connection.cancel_safe, psycopg 3.2+ on libpq 17+); detected "
            f"{detected}. {remedy}"
        ) from exc


class PostgresConnectionUnavailable(RuntimeError):
    pass


def _connect_with_backoff(
    connect: Callable[[], Any],
    connection_error: type[Exception],
    backoff: Callable[[float], None],
) -> Any:
    for delay in _RECONNECT_BACKOFF_SECONDS:
        try:
            return connect()
        except connection_error:
            backoff(delay)
    return connect()


def connect_postgres(
    dsn: str,
    *,
    backoff: Callable[[float], None] = time.sleep,
) -> SerializedPostgresConnection:
    try:
        import psycopg
    except ImportError as exc:
        raise PostgresDriverUnavailable(  # noqa: TRY003  # noqa: GENERIC_ERR_OK - preserve API
            "Postgres support requires `pip install vinctor-core[postgres]`"
        ) from exc
    require_supported_libpq()
    reconnect = partial(
        _connect_with_backoff,
        partial(psycopg.connect, dsn),
        psycopg.OperationalError,
        backoff,
    )
    return SerializedPostgresConnection(
        psycopg.connect(dsn),
        reconnect=reconnect,
        ambiguous_commit_errors=(psycopg.OperationalError,),
        replacement_validator=_validate_replacement_schema,
    )


def connect_postgres_readiness(dsn: str, *, timeout_seconds: float) -> Any:
    """Open a connection used only by the readiness probe.

    Bounds have to live in the driver and the server, not only in the caller: a
    deadline that bounds the waiter still leaves the query running and its
    session pinned, which is how a wedged probe kept a backend connection for
    the life of the process (PKA-146). ``connect_timeout`` caps the handshake,
    TCP keepalives make the kernel fail a black-holed socket instead of blocking
    on it forever, and the session timeouts make the server end the statement
    and the session on its own. ``autocommit`` keeps a failed probe from leaving
    an idle-in-transaction session behind.

    The timeouts are issued as SET rather than passed as libpq ``options`` so an
    operator's own ``options`` in the DSN survive.
    """
    import psycopg

    # Defence in depth: this is a public re-export (see postgres.py), so it must
    # not depend on connect_postgres having been called first.
    require_supported_libpq()
    bound_ms = max(int(timeout_seconds * 1000), 1)
    keepalive_seconds = max(int(timeout_seconds), 1)
    options: dict[str, Any] = {
        "autocommit": True,
        "connect_timeout": max(int(math.ceil(timeout_seconds)), 1),
        "keepalives": 1,
        "keepalives_idle": keepalive_seconds,
        "keepalives_interval": keepalive_seconds,
        "keepalives_count": 2,
    }
    # The only bound in this list that a CLIENT can enforce against a
    # black-holed socket. statement_timeout is enforced by a server we may not
    # be able to reach; keepalives do not fire while data is unacknowledged,
    # which is that exact case; connect_timeout covers the handshake only.
    # Nothing on this connection is legitimately slower than the readiness
    # bound, so unacknowledged data past it is a dead socket. Unconditional:
    # libpq 17+ is required, well past the 12 that introduced this option.
    # Honoured on Linux; accepted and ignored elsewhere — see the note in
    # docs/deployment/postgres.md.
    options["tcp_user_timeout"] = bound_ms
    connection = psycopg.connect(dsn, **options)
    try:
        connection.execute(f"SET statement_timeout = {bound_ms}")
        connection.execute(f"SET lock_timeout = {bound_ms}")
        connection.execute(f"SET idle_in_transaction_session_timeout = {bound_ms}")
    except BaseException:
        connection.close()
        raise
    return connection


def _validate_replacement_schema(connection: Any) -> None:
    from vinctor_service.postgres import _assert_postgres_schema_supported

    _assert_postgres_schema_supported(connection)


def _run_fail_open(emission: Callable[[], None]) -> None:
    # A raising anchor/export sink must never surface into the enforce path or
    # unwind the persisted audit row (mirrors sqlite_txn._run_fail_open).
    try:
        emission()
    except Exception as exc:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK - fail-open
        sys.stderr.write(f"vinctor: audit post-commit emission raised: {exc}\n")


class SerializedPostgresConnection:
    """Keep one psycopg connection's transaction scopes thread-safe.

    The stdlib HTTP runtime is threaded. Psycopg serializes statements on a
    connection, but its transaction is shared by all cursors, so a lock must
    cover each complete transaction rather than only individual statements.
    Separate service processes still use separate connections and coordinate
    through Postgres constraints and advisory locks.
    """

    def __init__(
        self,
        connection: Any,
        *,
        reconnect: Callable[[], Any] | None = None,
        ambiguous_commit_errors: tuple[type[Exception], ...] = (),
        replacement_validator: Callable[[Any], None] | None = None,
    ) -> None:
        self._connection = connection
        self._reconnect = reconnect
        self._ambiguous_commit_errors = ambiguous_commit_errors
        self._compatibility_validators = (
            [] if replacement_validator is None else [replacement_validator]
        )
        self._readiness_validators: list[Callable[[Any], None]] = []
        self._generation = 1
        self._quarantined = False
        self._lock = threading.RLock()
        # Stack of post-commit deferral scopes for the currently open
        # transaction tree (PKA-57). The outermost transaction() owns the
        # commit boundary; audit anchor/export emissions queued via
        # emit_or_defer are held until it commits and dropped if it rolls back,
        # so a rolled-back audit row never publishes an anchor/export. Guarded
        # by the connection lock, which the outermost transaction() holds for
        # the whole transaction, so only one thread ever mutates it at a time.
        self._deferral_scopes: list[list[Callable[[], None]]] = []

    @property
    def lock(self) -> threading.RLock:
        """The re-entrant lock serializing every transaction scope on this connection.

        A scope that must inspect connection-global state before opening its
        transaction acquires this first: ``info.transaction_status`` describes
        the connection, not the calling thread, so reading it unlocked cannot
        tell a peer thread's open transaction from this thread's caller nesting.
        """
        return self._lock

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    @property
    def is_quarantined(self) -> bool:
        with self._lock:
            return self._quarantined

    @property
    def is_ready(self) -> bool:
        # Deliberately lock-free. The readiness probe reads this, and this lock
        # is held for the whole of every enforce transaction: taking it here
        # would let one wedged request park every readiness worker in turn, the
        # PKA-146 failure in a new place. Both reads are single attribute loads,
        # and every interleaving of quarantine (connection cleared, then flag
        # set) and recovery (connection set, then flag cleared) reports False,
        # so a torn read fails closed and the next probe corrects it.
        return self._connection is not None and not self._quarantined

    def add_replacement_validator(self, validator: Callable[[Any], None]) -> None:
        with self._lock:
            self._compatibility_validators.append(validator)

    def add_readiness_validator(self, validator: Callable[[Any], None]) -> None:
        with self._lock:
            self._readiness_validators.append(validator)

    def _active_connection(self) -> Any:
        connection = self._connection
        if self._deferral_scopes:
            if connection is None:
                raise PostgresConnectionUnavailable("PostgreSQL connection is unavailable")
            return connection
        if connection is not None and not (
            bool(getattr(connection, "closed", False)) or bool(getattr(connection, "broken", False))
        ):
            return connection
        if self._reconnect is None:
            raise PostgresConnectionUnavailable("PostgreSQL connection is unavailable")
        if connection is not None:
            self._connection = None
            self._generation += 1
            self._quarantined = True
            connection.close()
        replacement = self._reconnect()
        try:
            validate_replacement_candidate(
                replacement,
                tuple(self._compatibility_validators + self._readiness_validators),
            )
        except BaseException:
            replacement.close()
            raise
        self._connection = replacement
        self._quarantined = False
        return replacement

    @staticmethod
    def _in_transaction(connection: Any) -> bool:
        # PQTRANS_IDLE == 0; any other status means a transaction is open on the
        # connection (an explicit one, OR an implicit one psycopg started for a
        # bare execute in the default non-autocommit mode).
        return int(connection.info.transaction_status) != 0

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self._lock:
            connection = self._active_connection()
            generation = self._generation
            # This scope owns the commit boundary only when it opens the REAL
            # transaction — i.e. the connection was idle on entry. If a
            # transaction is already open (a tracked parent scope, or an
            # implicit transaction from a bare execute), psycopg opens a
            # SAVEPOINT instead, whose release is NOT a durable commit, so this
            # scope must not flush. Determining this from transaction_status
            # rather than the scope stack alone closes the implicit-transaction
            # gap where an untracked BEGIN would be mistaken for the boundary.
            is_commit_boundary = not self._in_transaction(connection)
            scope: list[Callable[[], None]] = []
            self._deferral_scopes.append(scope)
            committed = False
            entered = False
            body_completed = False
            ambiguous = False
            try:
                with connection.transaction():
                    entered = True
                    yield
                    body_completed = True
                committed = True
            except BaseException as exc:
                ambiguous = (
                    is_commit_boundary
                    and entered
                    and body_completed
                    and isinstance(exc, self._ambiguous_commit_errors)
                )
                if not ambiguous:
                    raise
            finally:
                self._deferral_scopes.pop()
                # A nested savepoint that committed hands its deferred emissions
                # to its enclosing tracked scope, so they flush only when the
                # OUTERMOST transaction commits (and are dropped with it if the
                # outer transaction later rolls back). A scope whose
                # transaction/savepoint rolled back is simply discarded. If the
                # outer transaction is UNTRACKED (an implicit txn), there is no
                # post-commit hook to flush through, so the emissions are dropped
                # rather than published for a not-yet-committed row — anchor and
                # export are fail-open.
                if committed and not is_commit_boundary and self._deferral_scopes:
                    self._deferral_scopes[-1].extend(scope)
            if ambiguous:
                self._quarantine_locked(generation)
                raise AmbiguousCommitError from None
            if committed and is_commit_boundary:
                for emission in scope:
                    _run_fail_open(emission)

    @contextmanager
    def fresh_authoritative_read(self, *, after_generation: int) -> Iterator[None]:
        with self._lock:
            if self._generation <= after_generation:
                self._quarantine_locked(after_generation)
            if self._generation <= after_generation:
                raise PostgresConnectionUnavailable("fresh PostgreSQL generation is unavailable")
            with self.transaction():
                yield

    @contextmanager
    def fresh_authoritative_recovery(
        self,
        *,
        after_generation: int,
    ) -> Iterator[Any]:
        with self._lock:
            if self._generation <= after_generation:
                self._quarantine_locked(after_generation)
            if self._generation <= after_generation or self._reconnect is None:
                raise PostgresConnectionUnavailable("fresh PostgreSQL generation is unavailable")
            with one_shot_authoritative_recovery(
                self._reconnect,
                self._ambiguous_commit_errors,
                tuple(self._compatibility_validators),
            ) as authority:
                yield authority

    def quarantine_after_ambiguous_commit(self, expected_generation: int) -> bool:
        with self._lock:
            return self._quarantine_locked(expected_generation)

    def _quarantine_locked(self, expected_generation: int) -> bool:
        if expected_generation != self._generation or self._quarantined or self._connection is None:
            return False
        connection = self._connection
        self._connection = None
        self._generation += 1
        self._quarantined = True
        self._deferral_scopes.clear()
        with suppress(Exception):
            connection.close()
        return True

    def emit_or_defer(self, emission: Callable[[], None]) -> None:
        """Defer a post-commit audit side effect (anchor/export) to the open
        transaction's outermost commit, or run it inline when the connection is
        idle (the row is already committed). Fail-open (PKA-57)."""
        with self._lock:
            if self._deferral_scopes:
                self._deferral_scopes[-1].append(emission)
                return
            # No tracked scope: run inline ONLY when the connection is idle, so
            # the durable row is already committed. If an untracked transaction
            # is open (an implicit txn from a bare execute), running inline would
            # publish a not-yet-committed row, so drop instead (fail-open).
            if self._in_transaction(self._connection):
                return
        _run_fail_open(emission)

    def execute(self, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return self._active_connection().execute(*args, **kwargs)

    def close(self) -> None:
        with self._lock:
            self._reconnect = None
            connection = self._connection
            self._connection = None
            self._quarantined = True
            if connection is not None:
                connection.close()

    def __getattr__(self, name: str) -> Any:
        with self._lock:
            return getattr(self._active_connection(), name)
