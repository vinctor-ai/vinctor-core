"""Unit tests for SerializedSQLiteConnection — the wrapper that owns a
per-connection re-entrant lock and a per-thread audit-emission deferral queue as
instance state (replacing the id()-keyed module globals). Transaction SCOPES
hold the lock; the transaction-ending operations (commit/rollback/executescript)
also lock so a peer thread's transaction cannot be ended through the connection.
"""
from __future__ import annotations

import sqlite3
import threading

import pytest

from vinctor_service.sqlite_txn import SerializedSQLiteConnection, connect_sqlite


def _raw(tmp_path):
    return sqlite3.connect(str(tmp_path / "w.sqlite"), check_same_thread=False)


def test_execute_delegates_and_returns(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    conn.execute("CREATE TABLE t (n INTEGER)")
    conn.execute("INSERT INTO t VALUES (7)")
    assert conn.execute("SELECT n FROM t").fetchone()[0] == 7


def test_connect_sqlite_returns_wrapper(tmp_path):
    conn = connect_sqlite(str(tmp_path / "w.sqlite"))
    assert isinstance(conn, SerializedSQLiteConnection)
    conn.execute("SELECT 1")


def test_connect_sqlite_enables_wal_and_busy_timeout(tmp_path):
    conn = connect_sqlite(str(tmp_path / "wal.sqlite"))
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] > 0
    finally:
        conn.close()


def test_connect_sqlite_preserves_explicit_nonzero_timeout(tmp_path):
    conn = connect_sqlite(str(tmp_path / "timeout.sqlite"), timeout=0.125)
    try:
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 125
    finally:
        conn.close()


def test_connect_sqlite_warns_and_continues_when_wal_is_unavailable(
    tmp_path, capsys
):
    class WalUnavailableResult:
        def fetchone(self):
            return ("delete",)

    class WalUnavailableConnection(sqlite3.Connection):
        def execute(self, sql, *args, **kwargs):
            if sql == "PRAGMA journal_mode = WAL":
                return WalUnavailableResult()
            return super().execute(sql, *args, **kwargs)

    conn = connect_sqlite(
        str(tmp_path / "no-wal.sqlite"),
        factory=WalUnavailableConnection,
    )
    try:
        conn.execute("CREATE TABLE usable (value INTEGER)")
        conn.commit()
        assert conn.execute("SELECT COUNT(*) FROM usable").fetchone() == (0,)
    finally:
        conn.close()

    assert "WAL mode could not be enabled" in capsys.readouterr().err


def test_getattr_delegates(tmp_path):
    raw = _raw(tmp_path)
    conn = SerializedSQLiteConnection(raw)
    assert conn.in_transaction is False
    conn.executescript("CREATE TABLE t (n INTEGER);")
    conn.execute("INSERT INTO t VALUES (1)")
    assert conn.in_transaction is True  # delegated flag reflects the open write
    conn.commit()
    assert conn.in_transaction is False


def test_lock_is_reentrant(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    assert conn.lock is conn.lock
    # Re-entrant: a scope holding the lock can nest another scope (this is how
    # _write_scope / _atomic_write / key rotation nest same-thread).
    with conn.lock, conn.lock:
        pass


def test_commit_blocks_a_peer_thread_while_lock_held(tmp_path):
    # commit/rollback take the connection lock, so a peer thread cannot end
    # another thread's open transaction through the connection.
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    conn.executescript("CREATE TABLE t (n INTEGER);")
    holding = threading.Event()
    peer_done = threading.Event()
    release = threading.Event()

    def hold_lock():
        with conn.lock:
            holding.set()
            release.wait(timeout=2)

    def peer():
        holding.wait(timeout=2)
        conn.commit()
        peer_done.set()

    th, tp = threading.Thread(target=hold_lock), threading.Thread(target=peer)
    th.start()
    tp.start()
    try:
        assert holding.wait(timeout=2)
        assert not peer_done.wait(timeout=0.3)  # peer commit blocked on the lock
        release.set()
        assert peer_done.wait(timeout=2)
    finally:
        release.set()
        th.join(timeout=2)
        tp.join(timeout=2)


def test_cursor_is_unsupported(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    with pytest.raises(NotImplementedError):
        conn.cursor()


def test_require_serialized_rejects_raw(tmp_path):
    from vinctor_service.sqlite_txn import require_serialized

    wrapper = connect_sqlite(str(tmp_path / "w.sqlite"))
    assert require_serialized(wrapper) is wrapper  # a wrapper passes through
    with pytest.raises(TypeError):
        require_serialized(_raw(tmp_path))  # a raw connection is rejected


def test_setattr_delegates_to_connection(tmp_path):
    # row_factory (and other connection attributes) must land on the underlying
    # connection, not shadow it on the wrapper (drop-in contract).
    conn = connect_sqlite(str(tmp_path / "w.sqlite"))
    conn.row_factory = sqlite3.Row
    conn.executescript("CREATE TABLE t (n INTEGER); INSERT INTO t VALUES (5);")
    row = conn.execute("SELECT n FROM t").fetchone()
    assert row["n"] == 5  # Row access proves row_factory reached the connection


def test_context_manager_commits(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    conn.execute("CREATE TABLE t (n INTEGER)")
    conn.commit()
    with conn:
        conn.execute("INSERT INTO t VALUES (1)")
    assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 1


def test_context_manager_rolls_back_on_exception(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    conn.execute("CREATE TABLE t (n INTEGER)")
    conn.commit()
    with pytest.raises(RuntimeError), conn:
        conn.execute("INSERT INTO t VALUES (1)")
        raise RuntimeError("boom")
    assert conn.execute("SELECT COUNT(*) FROM t").fetchone()[0] == 0


def test_context_manager_releases_lock_after_exit(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    conn.execute("CREATE TABLE t (n INTEGER)")
    conn.commit()
    with conn:
        conn.execute("INSERT INTO t VALUES (1)")
    # A fresh thread can still acquire the lock (it was released on __exit__).
    acquired = threading.Event()

    def grab():
        with conn.lock:
            acquired.set()

    t = threading.Thread(target=grab)
    t.start()
    assert acquired.wait(timeout=2)
    t.join(timeout=2)


def test_deferral_flushes_on_normal_exit(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    ran = []
    with conn.atomic_write_deferral():
        conn.emit_or_defer(lambda: ran.append("a"))
        assert ran == []  # deferred, not run yet
    assert ran == ["a"]  # flushed after the scope


def test_deferral_drops_on_exception(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    ran = []
    with pytest.raises(RuntimeError), conn.atomic_write_deferral():
        conn.emit_or_defer(lambda: ran.append("a"))
        raise RuntimeError("rollback")
    assert ran == []  # discarded, never flushed


def test_emit_inline_when_no_scope(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    ran = []
    conn.emit_or_defer(lambda: ran.append("a"))
    assert ran == ["a"]  # no active scope: runs immediately


def test_deferral_is_per_connection(tmp_path):
    # A standalone emit on connection B inside connection A's deferral scope must
    # run inline (B's row is already committed; A's rollback must not drop it).
    a = SerializedSQLiteConnection(_raw(tmp_path))
    b = SerializedSQLiteConnection(sqlite3.connect(str(tmp_path / "b.sqlite")))
    ran = []
    with pytest.raises(RuntimeError), a.atomic_write_deferral():
        b.emit_or_defer(lambda: ran.append("b"))  # not captured by A
        assert ran == ["b"]  # ran inline
        raise RuntimeError("A rolls back")
    assert ran == ["b"]  # B's emission survived A's rollback


def test_deferral_is_per_thread(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    ran = []
    in_scope = threading.Event()
    release = threading.Event()

    def owner():
        with conn.atomic_write_deferral():
            in_scope.set()
            release.wait(timeout=2)

    t = threading.Thread(target=owner)
    t.start()
    try:
        assert in_scope.wait(timeout=2)
        # A different thread with no active scope emits inline even though the
        # owner thread's scope is open.
        conn.emit_or_defer(lambda: ran.append("other"))
        assert ran == ["other"]
    finally:
        release.set()
        t.join(timeout=2)


def test_deferral_fail_open(tmp_path):
    conn = SerializedSQLiteConnection(_raw(tmp_path))

    def boom():
        raise RuntimeError("sink down")

    # A raising emission must not propagate out of the flush (fail-open).
    with conn.atomic_write_deferral():
        conn.emit_or_defer(boom)
    # no exception


def test_drop_in_for_module_function(tmp_path):
    # The wrapper must be substitutable where a raw sqlite3.Connection is
    # expected by a module function that only reads.
    from vinctor_service.sqlite import get_sqlite_schema_versions, init_sqlite_schema

    conn = connect_sqlite(str(tmp_path / "w.sqlite"))
    init_sqlite_schema(conn)
    assert len(get_sqlite_schema_versions(conn)) > 0


@pytest.mark.parametrize("attr", ["cursor", "executemany", "blobopen", "deserialize"])
def test_denied_write_channels_raise(tmp_path, attr):
    # Unsynchronized write/statement channels are refused — they would bypass
    # the scope lock (none are used internally).
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    with pytest.raises(NotImplementedError):
        getattr(conn, attr)


def test_setting_transaction_control_rejected(tmp_path):
    # isolation_level / autocommit change the transaction semantics the scopes
    # rely on; setting them through the wrapper is refused.
    conn = SerializedSQLiteConnection(_raw(tmp_path))
    with pytest.raises(AttributeError):
        conn.isolation_level = None
    with pytest.raises(AttributeError):
        conn.autocommit = True


def test_autocommit_connection_rejected_at_construction(tmp_path):
    # An autocommit raw connection cannot be rolled back by the write scopes, so
    # it is refused at construction.
    raw = sqlite3.connect(str(tmp_path / "ac.sqlite"), isolation_level=None)
    with pytest.raises(ValueError):
        SerializedSQLiteConnection(raw)


def test_service_rejects_raw_connection(tmp_path):
    # P1a single-ownership: the service is not a wrapping root — it requires a
    # connection already opened by connect_sqlite, so two services on one
    # physical connection cannot mint two independent locks.
    from vinctor_service import SQLiteV1Service

    with pytest.raises(TypeError):
        SQLiteV1Service(sqlite3.connect(str(tmp_path / "s.sqlite")))
