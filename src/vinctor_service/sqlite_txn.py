"""Shared SQLite transaction primitives.

``SerializedSQLiteConnection`` wraps one sqlite3 connection so every transaction
scope runs under a single per-connection re-entrant lock, and owns the
per-thread after-commit audit-emission queue as instance state. It
lives here (not in ``sqlite``) so both ``sqlite`` and ``keys`` — which
``sqlite`` imports — can share the one lock for a connection without a circular
import.
"""
from __future__ import annotations

import fcntl
import os
import sqlite3
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from urllib.parse import unquote, urlsplit

DEFAULT_BUSY_TIMEOUT_MS = 5_000


def conn_txn_lock(conn: SerializedSQLiteConnection) -> threading.RLock:
    """Return the re-entrant lock that serializes transaction scopes on ``conn``.

    EVERY write / transaction scope on a connection runs under this lock so two
    threads sharing one connection cannot interleave — or one commit or join
    another's open transaction through the shared ``in_transaction`` flag. The
    lock is owned by the connection wrapper, so this is a thin accessor kept for
    the existing call sites.
    """
    return conn.lock


def _run_fail_open(emission: Callable[[], None]) -> None:
    # A raising anchor/export sink must never surface into the enforce path or
    # unwind the persisted audit row.
    try:
        emission()
    except Exception as exc:  # noqa: BLE001 - deliberate fail-open
        sys.stderr.write(f"vinctor: audit post-commit emission raised: {exc}\n")


_OWN_ATTRS = frozenset({"_connection", "_lock", "_deferral", "_database_lease"})

# Unsynchronized write / statement channels on sqlite3.Connection that would
# bypass the scope lock. Rejected outright — no internal caller uses any of them.
# execute() stays delegated (reads + scope-serialized writes); backup / iterdump
# / serialize are read-side and left delegated.
_DENIED_ATTRS = frozenset({"cursor", "executemany", "blobopen", "deserialize"})
# Attributes that change transaction semantics the write scopes depend on.
_TXN_CONTROL_ATTRS = frozenset({"isolation_level", "autocommit"})


def _is_autocommit(connection: sqlite3.Connection) -> bool:
    # Legacy autocommit (all versions): isolation_level is None. Explicit
    # autocommit (3.12+): the autocommit property is True. Either mode means a
    # native `with conn:` cannot roll a failed write back.
    if connection.isolation_level is None:
        return True
    return getattr(connection, "autocommit", False) is True


def _database_lock_path(database: str | os.PathLike[str]) -> Path | None:
    """Return the stable sibling lock path for a filesystem SQLite database.

    The lock must not live on the database inode itself: ``os.replace`` changes
    that inode, which would let a new opener lock the replacement while the
    storage operation still holds a lock on the old file. A sibling path stays
    stable across the rename.
    """
    value = os.fspath(database)
    if value == ":memory:":
        return None
    if value.startswith("file:"):
        parsed = urlsplit(value)
        if parsed.path in {"", ":memory:"}:
            return None
        value = unquote(parsed.path)
    return Path(f"{value}.vinctor.lock")


class SQLiteDatabaseLease:
    """Process-wide cooperative lease used by every Vinctor SQLite opener."""

    def __init__(
        self,
        database: str | os.PathLike[str],
        *,
        exclusive: bool,
        blocking: bool,
    ) -> None:
        self._path = _database_lock_path(database)
        self._fd: int | None = None
        if self._path is None:
            return
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            operation |= fcntl.LOCK_NB
        try:
            fcntl.flock(fd, operation)
        except BlockingIOError as error:
            os.close(fd)
            raise RuntimeError(
                f"SQLite database is in use: {database}; stop the service and "
                "close every Vinctor connection before reset/restore"
            ) from error
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def close(self) -> None:
        fd = self._fd
        if fd is None:
            return
        self._fd = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> SQLiteDatabaseLease:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def __del__(self) -> None:
        # sqlite3 connections are sometimes consumed through one-shot CLI
        # helper objects rather than explicitly closed. Match sqlite3's own
        # finalizer so such a connection cannot leave its cooperative lease
        # held until process exit.
        with suppress(Exception):
            self.close()


def exclusive_sqlite_database_lease(
    database: str | os.PathLike[str],
) -> SQLiteDatabaseLease:
    """Acquire reset/restore ownership, failing if any Vinctor handle is open."""
    return SQLiteDatabaseLease(database, exclusive=True, blocking=False)


class SerializedSQLiteConnection:
    """Wrap one sqlite3 connection so every transaction SCOPE runs under one
    per-connection re-entrant lock, and own the per-thread after-commit
    audit-emission queue as instance state.

    Mirrors ``SerializedPostgresConnection``. Because ``sqlite3.Connection`` can
    hold neither an attribute nor a weakref, the lock and the queue live on THIS
    wrapper rather than the underlying connection — so there is no id()-keyed
    global registry. There must be exactly ONE wrapper per physical connection
    (two wrappers = two locks = no mutual exclusion); construct it once at the
    service/factory boundary and pass it everywhere (see ``require_serialized``).

    Serialization follows the scope model: ``_write_scope`` / ``_atomic_write``
    / key rotation / policy apply hold ``lock`` across their whole BEGIN
    IMMEDIATE unit of work, so the individual statements inside them are
    serialized by that scope. Reads outside a scope are lock-free (as before the
    wrapper). The wrapper additionally locks the operations that END a
    transaction — ``commit`` / ``rollback`` / ``executescript`` (which implicitly
    commits) — so a direct call cannot commit or roll back a peer thread's open
    transaction through the shared connection. The unsynchronized write channels
    ``cursor`` / ``executemany`` / ``blobopen`` / ``deserialize`` are rejected,
    setting ``isolation_level`` / ``autocommit`` is rejected, and an autocommit
    connection is refused at construction — all would let a write escape the
    scope lock. ``execute()`` stays delegated (reads and scope-serialized
    writes); an embedder issuing raw write SQL through it is out of scope.
    """

    def __init__(
        self,
        connection: sqlite3.Connection,
        *,
        database_lease: SQLiteDatabaseLease | None = None,
    ) -> None:
        if _is_autocommit(connection):
            if database_lease is not None:
                database_lease.close()
            raise ValueError(
                "SerializedSQLiteConnection requires a connection in the default "
                "deferred-transaction mode; an autocommit connection "
                "(isolation_level=None / autocommit=True) cannot be rolled back "
                "by the write scopes"
            )
        self._connection = connection
        self._lock = threading.RLock()
        self._deferral = threading.local()
        self._database_lease = database_lease

    @property
    def lock(self) -> threading.RLock:
        """The re-entrant lock serializing every scope on this connection.

        ``_write_scope`` / ``_atomic_write`` / key rotation / policy apply
        acquire it before opening their BEGIN IMMEDIATE unit of work; being
        re-entrant, same-thread nesting does not deadlock.
        """
        return self._lock

    def close(self) -> None:
        try:
            with self._lock:
                self._connection.close()
        finally:
            if self._database_lease is not None:
                self._database_lease.close()
                self._database_lease = None

    def commit(self) -> None:
        with self._lock:
            self._connection.commit()

    def rollback(self) -> None:
        with self._lock:
            self._connection.rollback()

    def executescript(self, *args: object, **kwargs: object):
        with self._lock:
            return self._connection.executescript(*args, **kwargs)

    def __enter__(self) -> SerializedSQLiteConnection:
        # sqlite3's native `with conn:` transaction CM, held under the lock so a
        # bare write scope cannot interleave with a peer thread on this
        # connection.
        self._lock.acquire()
        try:
            self._connection.__enter__()
        except BaseException:
            self._lock.release()
            raise
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        try:
            return self._connection.__exit__(exc_type, exc, tb)
        finally:
            self._lock.release()

    def __getattr__(self, name: str) -> object:
        # execute() and read-only attributes (in_transaction, row_factory, …)
        # delegate to the underlying connection; writes are serialized by the
        # enclosing scope's lock. The unsynchronized write channels are refused.
        if name == "_connection":  # not yet set in __init__: avoid recursion
            raise AttributeError(name)
        if name in _DENIED_ATTRS:
            raise NotImplementedError(
                f"SerializedSQLiteConnection does not expose {name}(): it is an "
                "unsynchronized write/statement channel that would bypass the "
                "connection's transaction serialization — use execute() or a scope"
            )
        return getattr(self._connection, name)

    def __setattr__(self, name: str, value: object) -> None:
        # Wrapper-owned fields stay on the wrapper; ordinary connection
        # attributes (row_factory, text_factory, …) are set on the underlying
        # connection so the wrapper is a drop-in. Transaction-control attributes
        # are refused — changing them would break the scope model.
        if name in _OWN_ATTRS:
            object.__setattr__(self, name, value)
        elif name in _TXN_CONTROL_ATTRS:
            raise AttributeError(
                f"cannot set {name} on a SerializedSQLiteConnection: it changes "
                "the transaction semantics the write scopes depend on"
            )
        else:
            setattr(self._connection, name, value)

    def _scopes(self) -> list[list[Callable[[], None]]]:
        stack = getattr(self._deferral, "scopes", None)
        if stack is None:
            stack = []
            self._deferral.scopes = stack
        return stack

    @contextmanager
    def atomic_write_deferral(self) -> Iterator[None]:
        """Bracket an ``_atomic_write`` on THIS connection: deferred emissions
        flush after the scope exits normally, and are dropped on rollback / a
        failing commit inside it. Per-thread and per-connection, so a peer
        connection's already-committed emission is never captured or dropped by
        this scope."""
        stack = self._scopes()
        scope: list[Callable[[], None]] = []
        stack.append(scope)
        try:
            yield
        except BaseException:
            stack.pop()  # LIFO: this scope is the top; discard its emissions
            raise
        stack.pop()
        for emission in scope:
            _run_fail_open(emission)

    def emit_or_defer(self, emission: Callable[[], None]) -> None:
        """Defer a post-commit emission to the innermost active ``_atomic_write``
        scope on this connection+thread; if none is active, run it inline (the
        row is already committed)."""
        stack = self._scopes()
        if stack:
            stack[-1].append(emission)
            return
        _run_fail_open(emission)


def connect_sqlite(
    database: str | os.PathLike[str],
    *,
    _acquire_database_lease: bool = True,
    **kwargs: object,
) -> SerializedSQLiteConnection:
    """Open a serialized connection configured for bounded writer contention.

    A filesystem connection holds a shared lease for its whole lifetime.
    Reset/restore takes the corresponding exclusive lease before checkpointing,
    so it either owns the pathname through ``os.replace`` or fails before
    touching the destination. The lifetime scope is deliberate: an idle
    connection kept across a rename still points at the old inode and could
    otherwise recreate an old-database WAL beside the replacement later.
    ``_acquire_database_lease=False`` is reserved for reset/restore's private,
    unpredictable temp file, which is never the shared destination pathname.
    """
    database_lease = (
        SQLiteDatabaseLease(database, exclusive=False, blocking=True)
        if _acquire_database_lease
        else None
    )
    connection = None
    try:
        connection = sqlite3.connect(database, **kwargs)
        timeout_seconds = float(kwargs.get("timeout", DEFAULT_BUSY_TIMEOUT_MS / 1_000))
        busy_timeout_ms = max(1, int(timeout_seconds * 1_000))
        connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        try:
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        except sqlite3.Error as exc:
            sys.stderr.write(
                "vinctor: SQLite WAL mode could not be enabled; "
                f"continuing with the filesystem default: {exc}\n"
            )
        else:
            if mode not in {"wal", "memory"}:
                sys.stderr.write(
                    "vinctor: SQLite WAL mode could not be enabled "
                    f"(got {mode!r}); continuing with that journal mode\n"
                )
        return SerializedSQLiteConnection(connection, database_lease=database_lease)
    except BaseException:
        if connection is not None:
            connection.close()
        if database_lease is not None:
            database_lease.close()
        raise


def require_serialized(conn: object) -> SerializedSQLiteConnection:
    """Return ``conn`` if it is a wrapper, else raise — the single-ownership guard.

    The service, its repositories, and the module-level ``init_sqlite_schema`` /
    ``insert_grant`` all require an already-serialized connection so they cannot
    mint a second wrapper for a physical connection another already owns.
    ``connect_sqlite`` is the ONLY place that opens and wraps a raw connection
    (atomically), so there is exactly one wrapper — hence one lock — per
    physical connection without any id()-keyed registry.
    """
    if isinstance(conn, SerializedSQLiteConnection):
        return conn
    raise TypeError(
        "expected a SerializedSQLiteConnection (from connect_sqlite or a "
        "service's .conn); a raw sqlite3.Connection would create a second, "
        "un-coordinated lock for this connection"
    )
