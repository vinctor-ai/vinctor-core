"""Concurrent library callers sharing one SQLiteV1Service must not fold into a
single transaction (Codex P1): the per-connection lock serializes whole
transaction scopes, so one thread cannot join another's open transaction through
the shared ``in_transaction`` flag and have a rollback wipe both.
"""
from __future__ import annotations

import contextlib
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

import vinctor_service.sqlite as sqlite_mod
from vinctor_service import GrantRequestCreateRequest, SQLiteV1Service
from vinctor_service.key_ops import rotate_workspace_key
from vinctor_service.keys import SQLiteLocalKeyRepository

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def test_atomic_write_serializes_scopes_across_threads(tmp_path: Path) -> None:
    conn = sqlite3.connect(str(tmp_path / "v.sqlite"), check_same_thread=False)
    a_inside = threading.Event()
    b_entered = threading.Event()
    release_a = threading.Event()

    def thread_a() -> None:
        with sqlite_mod._atomic_write(conn):
            a_inside.set()
            release_a.wait(timeout=2)

    def thread_b() -> None:
        a_inside.wait(timeout=2)  # A opens its transaction first
        with sqlite_mod._atomic_write(conn):
            b_entered.set()

    ta, tb = threading.Thread(target=thread_a), threading.Thread(target=thread_b)
    ta.start()
    tb.start()
    try:
        assert a_inside.wait(timeout=2)
        # While A holds the scope, B must be blocked on the per-connection lock
        # and must NOT have entered (without the lock B would see in_transaction
        # and immediately join A's transaction, setting this event).
        assert not b_entered.wait(timeout=0.3)
        release_a.set()
        assert b_entered.wait(timeout=2)  # B proceeds only after A releases
    finally:
        release_a.set()
        ta.join(timeout=2)
        tb.join(timeout=2)
        conn.close()


def test_policy_apply_transaction_serializes_across_threads(tmp_path: Path) -> None:
    # Policy apply and rollback both run inside _sqlite_apply_transaction, which
    # now takes the same per-connection lock, so an apply and a rollback (or two
    # rollbacks) on one connection cannot interleave (Codex P1 policy).
    from vinctor_service.policy_files import _sqlite_apply_transaction

    conn = sqlite3.connect(str(tmp_path / "v.sqlite"), check_same_thread=False)
    a_inside = threading.Event()
    b_entered = threading.Event()
    release_a = threading.Event()

    def thread_a() -> None:
        with _sqlite_apply_transaction(conn):
            a_inside.set()
            release_a.wait(timeout=2)

    def thread_b() -> None:
        a_inside.wait(timeout=2)
        with _sqlite_apply_transaction(conn):
            b_entered.set()

    ta, tb = threading.Thread(target=thread_a), threading.Thread(target=thread_b)
    ta.start()
    tb.start()
    try:
        assert a_inside.wait(timeout=2)
        assert not b_entered.wait(timeout=0.3)  # B blocked while A holds
        release_a.set()
        assert b_entered.wait(timeout=2)
    finally:
        release_a.set()
        ta.join(timeout=2)
        tb.join(timeout=2)
        conn.close()


def test_concurrent_rollback_does_not_erase_a_committed_call(tmp_path: Path) -> None:
    # End-to-end: a call that rolls back (its audit write fails) runs first and
    # holds the connection; a concurrent call, serialized behind it, then commits
    # and its request must survive.
    conn = sqlite3.connect(str(tmp_path / "v.sqlite"), check_same_thread=False)
    service = SQLiteV1Service(conn)
    real_write = service.audit_writer.write

    def wrapped_write(event):
        if event.grant_ref == "grq_fail":
            raise RuntimeError("audit write failed for the rolling-back call")
        return real_write(event)

    service.audit_writer.write = wrapped_write  # type: ignore[method-assign]

    def create(request_id: str) -> None:
        with contextlib.suppress(RuntimeError):
            service.create_grant_request(
                GrantRequestCreateRequest(
                    workspace_id="ws_main", requester_agent_id="agent_a",
                    requested_scopes=("execute:ci/test",), requested_ttl_seconds=3600,
                    reason="run CI", request_id=request_id,
                ),
                now=NOW,
            )

    threads = [
        threading.Thread(target=create, args=("grq_fail",)),
        threading.Thread(target=create, args=("grq_ok",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=3)

    assert service.grant_request_repository.get_request("grq_ok") is not None
    assert service.grant_request_repository.get_request("grq_fail") is None
    conn.close()


def test_settings_write_serializes_with_atomic_write(tmp_path: Path) -> None:
    # A settings write (now routed through the shared connection lock) must not
    # commit another thread's open _atomic_write transaction (Codex P1: the
    # unlocked `with self._conn:` in set_require_pop committed a peer's txn).
    conn = sqlite3.connect(str(tmp_path / "v.sqlite"), check_same_thread=False)
    service = SQLiteV1Service(conn)
    a_inside = threading.Event()
    b_done = threading.Event()
    release_a = threading.Event()

    def thread_a() -> None:
        with sqlite_mod._atomic_write(conn):
            a_inside.set()
            release_a.wait(timeout=2)

    def thread_b() -> None:
        a_inside.wait(timeout=2)
        service.agent_enforcement_settings_repository.set_require_pop(
            workspace_id="ws_main", agent_id="agent_a", require_pop=True, now=NOW
        )
        b_done.set()

    ta, tb = threading.Thread(target=thread_a), threading.Thread(target=thread_b)
    ta.start()
    tb.start()
    try:
        assert a_inside.wait(timeout=2)
        # The settings write is blocked on the connection lock, not committing A.
        assert not b_done.wait(timeout=0.3)
        release_a.set()
        assert b_done.wait(timeout=2)
    finally:
        release_a.set()
        ta.join(timeout=2)
        tb.join(timeout=2)
        conn.close()


def test_rotation_waits_for_another_threads_transaction(tmp_path: Path) -> None:
    # A rotation must not be REJECTED because another thread holds a transaction;
    # it should wait for the connection to become idle, then run (Codex P2: the
    # nesting check ran before the lock, mistaking a peer's txn for caller nesting).
    conn = sqlite3.connect(str(tmp_path / "v.sqlite"), check_same_thread=False)
    SQLiteV1Service(conn)  # initialize schema
    repo = SQLiteLocalKeyRepository(conn)
    old = repo.create_workspace_key(workspace_id="ws_main", now=NOW)
    a_inside = threading.Event()
    rotated = threading.Event()
    release_a = threading.Event()
    errors: list[Exception] = []

    def thread_a() -> None:
        with sqlite_mod._atomic_write(conn):
            a_inside.set()
            release_a.wait(timeout=2)

    def thread_b() -> None:
        a_inside.wait(timeout=2)
        try:
            rotate_workspace_key(repo, workspace_id="ws_main", now=NOW)
            rotated.set()
        except Exception as exc:  # noqa: BLE001 - captured for assertion
            errors.append(exc)

    ta, tb = threading.Thread(target=thread_a), threading.Thread(target=thread_b)
    ta.start()
    tb.start()
    try:
        assert a_inside.wait(timeout=2)
        # B is waiting on the lock, NOT rejected with "inside an open transaction".
        assert not rotated.wait(timeout=0.3)
        assert errors == []
        release_a.set()
        assert rotated.wait(timeout=2)
        assert errors == []
        assert repo.get_by_id(old.record.key_id).status == "revoked"
    finally:
        release_a.set()
        ta.join(timeout=2)
        tb.join(timeout=2)
        conn.close()
