"""A COMMIT that fails must never leave the connection in a transaction (PKA-224).

SQLite leaves the transaction OPEN when COMMIT returns SQLITE_BUSY. A scope that
commits *after* its `except` therefore propagates the error with the connection
still dirty, and every later write scope on that connection takes the "already
in a transaction" nesting path (`sqlite._write_scope`): the write joins an
orphaned transaction that nothing will ever commit. Enforce keeps answering
`permit` off a decision whose audit row never becomes durable, for as long as
the process lives.

Two scopes had that shape — `policy_files._sqlite_apply_transaction` and the key
rotation scope in `keys` — and this file pins the invariant for EVERY
BEGIN IMMEDIATE scope in the tree, including the ones that were already correct,
so a third cannot appear unnoticed.

Durability is asserted from an INDEPENDENT connection throughout: uncommitted
rows are visible on the writer's own connection, which is exactly why this
shipped.

Every identifier below is a decoy fixture.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import pytest

from vinctor_service import AgentIdentity, SQLiteV1Service, handle_v1_enforce_http
from vinctor_service.idempotency_models import AmbiguousCommitError
from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.models import GrantIssueRequest
from vinctor_service.policy_files import _sqlite_apply_transaction
from vinctor_service.sqlite_pool import SQLiteServicePool
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
AGENT_KEY = "agent_key_decoy"


def _seed(db_path: Path):
    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_decoy", agent_id="agent_decoy",
        scopes=("write:repo/feature/*",), now=NOW,
    )
    service.issue_grant(
        GrantIssueRequest(
            workspace_id="ws_decoy", target_agent_id="agent_decoy",
            requested_scopes=("write:repo/feature/*",), ttl_seconds=3600,
            grant_ref="grt_decoy",
        ),
        now=NOW,
    )
    # Fresh 0.6.0 databases require a boundary. These tests are about commit
    # durability, not boundary enforcement, so the mandate is turned off rather
    # than satisfied — same as test_audit_write_failure_fails_closed.
    service.agent_enforcement_settings_repository.set_require_boundary(
        workspace_id="ws_decoy",
        agent_id="agent_decoy",
        require_boundary=False,
        now=NOW,
    )
    return conn


def _durable_audit_rows(db_path: Path) -> int:
    reader = sqlite3.connect(db_path)
    try:
        return reader.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
    finally:
        reader.close()


@contextmanager
def _busy_commit(conn, db_path: Path) -> Iterator[None]:
    """Make the COMMIT that closes the enclosing scope return SQLITE_BUSY.

    In rollback-journal mode a COMMIT must promote the writer to EXCLUSIVE, and
    a concurrent reader holding SHARED blocks that — the textbook SQLITE_BUSY at
    COMMIT. WAL exists precisely so a reader does NOT block a writer, so this is
    reproduced in the journal mode where it actually happens; `connect_sqlite`
    tolerates a filesystem default it cannot upgrade to WAL (it warns on stderr
    and continues), so this is a configuration Vinctor really runs in.
    """
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.execute("PRAGMA busy_timeout = 50")
    reader = sqlite3.connect(db_path)
    try:
        yield reader
    finally:
        reader.rollback()
        reader.close()


def _hold_read_lock(reader: sqlite3.Connection) -> None:
    reader.execute("BEGIN")
    reader.execute("SELECT COUNT(*) FROM grants").fetchall()


# --- every BEGIN IMMEDIATE scope, same invariant -----------------------------


def test_policy_apply_scope_rolls_back_when_its_commit_is_busy(tmp_path: Path) -> None:
    db_path = tmp_path / "policy.sqlite"
    conn = _seed(db_path)
    try:
        with (
            _busy_commit(conn, db_path) as reader,
            pytest.raises(sqlite3.OperationalError, match="database is locked"),
            _sqlite_apply_transaction(conn),
        ):
            conn.execute(
                "UPDATE grants SET status = 'active' WHERE grant_ref = ?",
                ("grt_decoy",),
            )
            _hold_read_lock(reader)
        assert conn.in_transaction is False
    finally:
        conn.close()


def test_key_rotation_scope_rolls_back_when_its_commit_is_busy(tmp_path: Path) -> None:
    db_path = tmp_path / "keys.sqlite"
    conn = _seed(db_path)
    try:
        keys = SQLiteLocalKeyRepository(conn)
        with (
            _busy_commit(conn, db_path) as reader,
            pytest.raises(sqlite3.OperationalError, match="database is locked"),
            keys.transaction(),
        ):
            conn.execute(
                "UPDATE grants SET status = 'active' WHERE grant_ref = ?",
                ("grt_decoy",),
            )
            _hold_read_lock(reader)
        assert conn.in_transaction is False
    finally:
        conn.close()


def test_write_scope_rolls_back_when_its_commit_is_busy(tmp_path: Path) -> None:
    # The reference shape, pinned so the pattern the other scopes were fixed to
    # match cannot regress underneath them.
    from vinctor_service.sqlite import _write_scope

    db_path = tmp_path / "write.sqlite"
    conn = _seed(db_path)
    try:
        with (
            _busy_commit(conn, db_path) as reader,
            pytest.raises(sqlite3.OperationalError, match="database is locked"),
            _write_scope(conn),
        ):
            conn.execute(
                "UPDATE grants SET status = 'active' WHERE grant_ref = ?",
                ("grt_decoy",),
            )
            _hold_read_lock(reader)
        assert conn.in_transaction is False
    finally:
        conn.close()


def test_idempotency_scope_rolls_back_when_its_commit_is_busy(tmp_path: Path) -> None:
    # `SQLiteIdempotencyStore._transaction` uses sqlite3's native `with conn:`
    # rather than an explicit commit. That CM rolls back a failed COMMIT on
    # CPython >= 3.11 (it did NOT on 3.9), so the scope is correct today — but
    # only because of interpreter behaviour, which is worth pinning here.
    db_path = tmp_path / "idem.sqlite"
    conn = _seed(db_path)
    try:
        store = SQLiteIdempotencyStore(conn, keyring=None)
        # A failed COMMIT here is reported as ambiguous rather than as the raw
        # sqlite3 error; what matters for PKA-224 is the connection state it
        # leaves behind.
        with (
            _busy_commit(conn, db_path) as reader,
            pytest.raises(AmbiguousCommitError),
            store._transaction(),
        ):
            conn.execute(
                "UPDATE grants SET status = 'active' WHERE grant_ref = ?",
                ("grt_decoy",),
            )
            _hold_read_lock(reader)
        assert conn.in_transaction is False
    finally:
        conn.close()


# --- the consequence the scopes exist to prevent -----------------------------


def _enforce(conn):
    return handle_v1_enforce_http(
        headers={"X-Agent-Key": AGENT_KEY},
        body={"grant_ref": "grt_decoy", "action": "write",
              "resource": "repo/feature/readme"},
        agent_identities={
            AGENT_KEY: AgentIdentity(workspace_id="ws_decoy", agent_id="agent_decoy")
        },
        service=SQLiteV1Service(conn, initialize_schema=False),
        now=NOW,
    )


def test_no_permit_is_served_without_a_durable_audit_row_after_a_busy_commit(
    tmp_path: Path,
) -> None:
    """The reported failure, end to end.

    Before the fix: the failed commit left the connection dirty, three enforce
    calls returned 200 permit, and the durable audit row count never moved —
    while the writer's own connection reported all three rows.
    """
    db_path = tmp_path / "enforce.sqlite"
    conn = _seed(db_path)
    try:
        durable_before = _durable_audit_rows(db_path)

        with (
            _busy_commit(conn, db_path) as reader,
            pytest.raises(sqlite3.OperationalError),
            _sqlite_apply_transaction(conn),
        ):
            conn.execute(
                "UPDATE grants SET status = 'active' WHERE grant_ref = ?",
                ("grt_decoy",),
            )
            _hold_read_lock(reader)

        assert conn.in_transaction is False

        permits = 0
        for _ in range(3):
            response = _enforce(conn)
            assert response.status_code == 200
            assert response.body["decision"] == "permit"
            permits += 1

        # Every permit served is backed by a row a DIFFERENT connection can see.
        assert _durable_audit_rows(db_path) == durable_before + permits
    finally:
        conn.close()


# --- the pool must not keep serving a dirty connection ------------------------


def _open_pool(database: Path, *, size: int = 2) -> SQLiteServicePool:
    connection = connect_sqlite(database, check_same_thread=False)
    return SQLiteServicePool(
        database,
        primary_connection=connection,
        primary_service=SQLiteV1Service(connection),
        primary_key_repository=SQLiteLocalKeyRepository(connection),
        size=size,
    )


def test_pool_rolls_back_a_request_that_left_a_transaction_open(tmp_path: Path) -> None:
    pool = _open_pool(tmp_path / "pool.sqlite")
    try:
        with pool.request_scope():
            leaked = pool.current_context
            leaked.connection.execute("BEGIN IMMEDIATE")
            assert leaked.connection.in_transaction is True

        assert leaked.connection.in_transaction is False

        # Whichever context the next requests get, none of them may arrive
        # already inside a transaction.
        for _ in range(4):
            with pool.request_scope():
                assert pool.current_context.connection.in_transaction is False
    finally:
        pool.close()


class _UnrollbackableConnection:
    """A connection stuck in a transaction that rollback cannot clear."""

    def __init__(self, real: object) -> None:
        self._real = real

    @property
    def in_transaction(self) -> bool:
        return True

    def rollback(self) -> None:
        raise sqlite3.OperationalError("cannot roll back")

    def __getattr__(self, name: str) -> object:
        return getattr(self._real, name)


def test_pool_retires_a_context_it_cannot_clean(tmp_path: Path) -> None:
    pool = _open_pool(tmp_path / "retire.sqlite")
    try:
        with pool.request_scope():
            poisoned = pool.current_context
            poisoned.connection = _UnrollbackableConnection(poisoned.connection)

        # Not returned to service: dropped, closed, and replaced.
        assert poisoned.closed is True
        assert poisoned.healthy is False
        assert poisoned not in pool._contexts
        assert pool.capacity == 2

        for _ in range(4):
            with pool.request_scope():
                assert pool.current_context is not poisoned
                assert pool.current_context.connection.in_transaction is False
    finally:
        pool.close()
