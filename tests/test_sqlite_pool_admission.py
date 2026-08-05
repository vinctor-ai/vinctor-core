from __future__ import annotations

from pathlib import Path
from threading import Event, Thread

from idempotency_sqlite_fixtures import configured_pool


def test_size_one_pool_waits_for_release_then_leases_same_generation(tmp_path: Path) -> None:
    pool = configured_pool(tmp_path / "wait-release.sqlite3", size=1)
    first_entered = Event()
    release_first = Event()
    second_entered = Event()
    generations: list[int] = []
    failures: list[str] = []

    def first_request() -> None:
        with pool.request_scope():
            generations.append(pool.current_context.generation)
            first_entered.set()
            assert release_first.wait(timeout=5)

    def second_request() -> None:
        try:
            with pool.request_scope():
                generations.append(pool.current_context.generation)
                second_entered.set()
        except RuntimeError as error:
            failures.append(str(error))

    first = Thread(target=first_request)
    second = Thread(target=second_request)
    first.start()
    try:
        assert first_entered.wait(timeout=5)
        second.start()
        with pool._lease_condition:
            assert pool._lease_condition.wait_for(lambda: len(pool._waiters) == 1, timeout=5)
        assert not second_entered.is_set()
        release_first.set()
        second.join(timeout=5)
        assert not second.is_alive()
        assert second_entered.is_set()
        assert generations == [1, 1]
        assert failures == []
    finally:
        release_first.set()
        first.join(timeout=5)
        second.join(timeout=5)
        pool.close()


def test_close_wakes_blocked_lease_with_coarse_unavailable(tmp_path: Path) -> None:
    pool = configured_pool(tmp_path / "close-wakeup.sqlite3", size=1)
    holder_entered = Event()
    release_holder = Event()
    failures: list[str] = []

    def holder() -> None:
        with pool.request_scope():
            holder_entered.set()
            assert release_holder.wait(timeout=5)

    def waiter() -> None:
        try:
            with pool.request_scope():
                raise AssertionError("closed pool leased a context")
        except RuntimeError as error:
            failures.append(str(error))

    holder_thread = Thread(target=holder)
    waiter_thread = Thread(target=waiter)
    holder_thread.start()
    try:
        assert holder_entered.wait(timeout=5)
        waiter_thread.start()
        with pool._lease_condition:
            assert pool._lease_condition.wait_for(lambda: len(pool._waiters) == 1, timeout=5)
        pool.close()
        waiter_thread.join(timeout=1)
        assert not waiter_thread.is_alive()
        assert failures == ["SQLite service pool unavailable"]
    finally:
        release_holder.set()
        holder_thread.join(timeout=5)
        waiter_thread.join(timeout=5)
        pool.close()


def test_lease_wait_is_bounded_and_returns_coarse_unavailable(tmp_path: Path) -> None:
    pool = configured_pool(
        tmp_path / "timeout.sqlite3",
        size=1,
        lease_timeout_seconds=0.01,
    )
    failures: list[str] = []

    def waiter() -> None:
        try:
            with pool.request_scope():
                raise AssertionError("timed-out waiter leased a context")
        except RuntimeError as error:
            failures.append(str(error))

    try:
        with pool.request_scope():
            thread = Thread(target=waiter)
            thread.start()
            thread.join(timeout=1)
            assert not thread.is_alive()
        assert failures == ["SQLite service pool unavailable"]
    finally:
        pool.close()
