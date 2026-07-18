"""PKA-57: SerializedPostgresConnection post-commit deferral bookkeeping.

The Postgres integration tests (test_postgres_storage.py) are CI-only, so the
deferral scope logic that holds audit anchor/export emissions until the
OUTERMOST transaction commits — and drops them on rollback — is exercised here
against a fake connection whose ``transaction()`` mimics psycopg's
outer-transaction / nested-savepoint nesting (a nested exception propagates and
unwinds the whole tree). No real database is required.
"""
from __future__ import annotations

import pytest

from vinctor_service.postgres import SerializedPostgresConnection


class _FakeInfo:
    def __init__(self, conn: _FakePgConn) -> None:
        self._conn = conn

    @property
    def transaction_status(self) -> int:
        # PQTRANS_IDLE == 0 when no transaction is open, non-zero otherwise —
        # matches how psycopg reports an open (explicit or implicit) transaction.
        return 0 if self._conn.depth == 0 and not self._conn.implicit else 1


class _FakeTxn:
    def __init__(self, conn: _FakePgConn) -> None:
        self._conn = conn

    def __enter__(self) -> _FakeTxn:
        self._conn.depth += 1
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        self._conn.depth -= 1
        return False  # propagate exceptions, like psycopg on a failed txn


class _FakePgConn:
    def __init__(self, *, implicit: bool = False) -> None:
        self.depth = 0
        # Model an already-open implicit transaction (e.g. left by a bare
        # execute in psycopg's default non-autocommit mode).
        self.implicit = implicit
        self.info = _FakeInfo(self)

    def transaction(self) -> _FakeTxn:
        return _FakeTxn(self)


def _conn() -> SerializedPostgresConnection:
    return SerializedPostgresConnection(_FakePgConn())


def test_emit_or_defer_runs_inline_without_a_transaction() -> None:
    conn = _conn()
    ran: list[str] = []
    conn.emit_or_defer(lambda: ran.append("a"))
    assert ran == ["a"]


def test_emit_or_defer_deferred_until_outer_commit() -> None:
    conn = _conn()
    ran: list[str] = []
    with conn.transaction():
        conn.emit_or_defer(lambda: ran.append("a"))
        assert ran == []  # held while the transaction is open
    assert ran == ["a"]  # flushed after commit


def test_emit_or_defer_dropped_on_rollback() -> None:
    conn = _conn()
    ran: list[str] = []
    with pytest.raises(RuntimeError, match="boom"), conn.transaction():
        conn.emit_or_defer(lambda: ran.append("a"))
        raise RuntimeError("boom")
    assert ran == []  # never flushed for the rolled-back transaction


def test_nested_savepoint_emissions_flush_once_on_outer_commit() -> None:
    conn = _conn()
    ran: list[str] = []
    with conn.transaction():
        conn.emit_or_defer(lambda: ran.append("outer"))
        with conn.transaction():
            conn.emit_or_defer(lambda: ran.append("inner"))
            assert ran == []  # inner savepoint release does NOT flush
        assert ran == []  # still deferred to the outermost commit
    assert ran == ["outer", "inner"]


def test_nested_emissions_dropped_when_outer_rolls_back() -> None:
    conn = _conn()
    ran: list[str] = []
    with pytest.raises(RuntimeError, match="boom"), conn.transaction():
        with conn.transaction():
            conn.emit_or_defer(lambda: ran.append("inner"))
        # inner savepoint committed and merged into the outer scope...
        raise RuntimeError("boom")  # ...but the outer transaction rolls back
    assert ran == []  # merged emissions dropped with the outer rollback


def test_a_failing_emission_is_fail_open() -> None:
    conn = _conn()
    ran: list[str] = []

    def _boom() -> None:
        raise RuntimeError("sink down")

    with conn.transaction():
        conn.emit_or_defer(_boom)
        conn.emit_or_defer(lambda: ran.append("after"))
    # A raising sink is swallowed and does not stop the next emission.
    assert ran == ["after"]


def test_emission_not_published_when_an_untracked_transaction_is_open() -> None:
    # PKA-57 hardening (Codex P1): if an untracked transaction is already open
    # (e.g. an implicit txn from a bare execute), a transaction() opens only a
    # SAVEPOINT, whose release is not a durable commit. The scope must NOT be
    # treated as the commit boundary, so nothing is published for a row the
    # untracked outer transaction could still roll back.
    conn = SerializedPostgresConnection(_FakePgConn(implicit=True))
    ran: list[str] = []
    with conn.transaction():
        conn.emit_or_defer(lambda: ran.append("a"))
    # Savepoint released, but the untracked outer transaction has not committed.
    assert ran == []
    # emit_or_defer with no tracked scope but an open (untracked) transaction
    # also refuses to publish inline.
    conn.emit_or_defer(lambda: ran.append("b"))
    assert ran == []


def test_deferral_scopes_balanced_after_rollback() -> None:
    conn = _conn()
    with pytest.raises(RuntimeError), conn.transaction():
        raise RuntimeError("boom")
    # A later inline emission proves the scope stack unwound cleanly.
    ran: list[str] = []
    conn.emit_or_defer(lambda: ran.append("a"))
    assert ran == ["a"]
