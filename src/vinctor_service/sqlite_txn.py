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
# current thread's _atomic_write ON A SPECIFIC CONNECTION: an emission registered
# while that connection's atomic write is active runs only after IT commits, and
# is dropped if it rolls back or its commit fails. The scopes form a per-thread
# LIFO stack of (connection-id, emissions); an emission is captured by the
# innermost scope for ITS OWN connection, so a standalone write on connection B
# inside connection A's atomic write is NOT captured by A (it emits inline, since
# B's row is already committed and A's rollback must not drop it). No
# process-global growth: connection ids live only for the duration of a scope.
_local = threading.local()


def _scope_stack() -> list[list]:
    stack = getattr(_local, "scopes", None)
    if stack is None:
        stack = []
        _local.scopes = stack
    return stack


def _run_fail_open(emission: Callable[[], None]) -> None:
    # A raising anchor/export sink must never surface into the enforce path or
    # unwind the persisted audit row.
    try:
        emission()
    except Exception as exc:  # noqa: BLE001 - deliberate fail-open
        sys.stderr.write(f"vinctor: audit post-commit emission raised: {exc}\n")


@contextmanager
def atomic_write_deferral(conn: sqlite3.Connection) -> Iterator[None]:
    """Bracket an _atomic_write on ``conn`` so its deferred emissions flush on
    commit and are dropped on rollback / a failing commit inside the scope.
    Scoped to this connection: emissions on OTHER connections during this scope
    belong to their own scope (or emit inline), so a peer connection's rollback
    can never drop this connection's committed emission and vice versa."""
    stack = _scope_stack()
    scope: list = [id(conn), []]
    stack.append(scope)
    try:
        yield
    except BaseException:
        stack.pop()  # LIFO: this scope is the top; discard its queued emissions
        raise
    stack.pop()
    for emission in scope[1]:
        _run_fail_open(emission)


def emit_or_defer(conn: sqlite3.Connection, emission: Callable[[], None]) -> None:
    """Defer a post-commit audit emission to the innermost active _atomic_write
    scope FOR ``conn`` on the current thread; if none is active, run it inline
    (the row is already committed)."""
    cid = id(conn)
    for scope in reversed(_scope_stack()):
        if scope[0] == cid:
            scope[1].append(emission)
            return
    _run_fail_open(emission)
