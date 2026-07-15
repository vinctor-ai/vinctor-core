"""Shared SQLite transaction primitives: a per-connection re-entrant lock that
serializes every transaction scope on a connection, and a thread-local
after-commit queue for audit anchor/export emissions.

Lives in its own module so both ``sqlite`` and ``keys`` (which ``sqlite``
imports) can acquire the SAME lock for one connection without a circular import.
"""
from __future__ import annotations

import sqlite3
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

# sqlite3.Connection can hold neither an attribute nor a weakref, so the
# per-connection re-entrant lock is keyed by id(). A connection is long-lived
# (one per service), so the map stays tiny; if an id is reused after a
# connection is collected, the reused lock is simply un-contended (the old
# connection is gone), which is harmless.
_CONN_TXN_LOCKS: dict[int, threading.RLock] = {}
_CONN_TXN_LOCKS_GUARD = threading.Lock()


def conn_txn_lock(conn: sqlite3.Connection) -> threading.RLock:
    """Return the re-entrant lock that serializes transaction scopes on ``conn``.

    EVERY write / transaction scope on a connection must run under this lock so
    two threads sharing one connection cannot interleave — or one commit or
    join another's open transaction through the shared ``in_transaction`` flag.
    """
    lock = _CONN_TXN_LOCKS.get(id(conn))
    if lock is None:
        with _CONN_TXN_LOCKS_GUARD:
            lock = _CONN_TXN_LOCKS.get(id(conn))
            if lock is None:
                lock = threading.RLock()
                _CONN_TXN_LOCKS[id(conn)] = lock
    return lock


# Deferred post-commit audit emissions (external anchor / export). Scoped to the
# current thread's _atomic_write: an emission registered while an atomic write is
# active runs only after that write COMMITS, and is dropped if it rolls back or
# its commit fails. Thread-local (not keyed by connection) because an audit write
# always runs on the same thread as the _atomic_write wrapping it — so there is
# no process-global growth and no way for a stale callback to leak into a later,
# unrelated transaction. Outside an _atomic_write the emission runs inline.
_local = threading.local()


def _run_fail_open(emission: Callable[[], None]) -> None:
    # A raising anchor/export sink must never surface into the enforce path or
    # unwind the persisted audit row.
    try:
        emission()
    except Exception as exc:  # noqa: BLE001 - deliberate fail-open
        sys.stderr.write(f"vinctor: audit post-commit emission raised: {exc}\n")


@contextmanager
def atomic_write_deferral() -> Iterator[None]:
    """Bracket an _atomic_write so deferred emissions flush on commit, drop on
    rollback/commit-failure. Re-entrant per thread: only the outermost scope
    flushes, and any exception (including a failing commit inside the scope)
    discards the whole batch."""
    depth = getattr(_local, "depth", 0)
    if depth == 0:
        _local.emissions = []
    _local.depth = depth + 1
    try:
        yield
    except BaseException:
        _local.depth -= 1
        if _local.depth == 0:
            _local.emissions = []
        raise
    _local.depth -= 1
    if _local.depth == 0:
        emissions = _local.emissions
        _local.emissions = []
        for emission in emissions:
            _run_fail_open(emission)


def emit_or_defer(emission: Callable[[], None]) -> None:
    """Defer a post-commit audit emission to the current thread's atomic write if
    one is active, otherwise run it inline (the row is already committed)."""
    if getattr(_local, "depth", 0) > 0:
        _local.emissions.append(emission)
    else:
        _run_fail_open(emission)
