"""Durable SQLite-backed PoP replay store (ADR 0007 arc J).

Mirrors the in-memory ``PopReplayCache`` contract (see ``test_pop.py``) but on a
SQLite store, plus the durability property the in-memory cache cannot provide:
state survives a process restart (a fresh connection on the same db file).
"""

import sqlite3

from vinctor_service.sqlite import (
    SQLiteReplayStore,
    get_sqlite_schema_versions,
    init_sqlite_schema,
)

SKEW = 60


def _conn(path) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    init_sqlite_schema(conn)
    return conn


def test_sqlite_replay_first_seen_then_replay(tmp_path) -> None:
    store = SQLiteReplayStore(_conn(tmp_path / "v.sqlite"))
    now_unix = 1_000_000
    assert (
        store.check_and_record(
            token_id="t", nonce="n1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is True
    )
    # identical (token_id, nonce) -> replay
    assert (
        store.check_and_record(
            token_id="t", nonce="n1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is False
    )


def test_sqlite_replay_durable_across_restart(tmp_path) -> None:
    db = tmp_path / "v.sqlite"
    now_unix = 1_000_000
    store = SQLiteReplayStore(_conn(db))
    assert (
        store.check_and_record(
            token_id="t", nonce="n1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is True
    )
    # Simulate a restart: a brand-new connection on the SAME db file. The
    # in-memory cache would forget; the durable store must still deny.
    store2 = SQLiteReplayStore(_conn(db))
    assert (
        store2.check_and_record(
            token_id="t", nonce="n1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is False
    )


def test_sqlite_replay_full_of_fresh_entries_fails_closed(tmp_path) -> None:
    store = SQLiteReplayStore(_conn(tmp_path / "v.sqlite"), max_entries=1)
    now_unix = 1_000_000
    assert (
        store.check_and_record(
            token_id="t", nonce="n1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is True
    )
    # a second distinct, fresh nonce -> rejected (fail closed), never evicting
    # the held fresh entry.
    assert (
        store.check_and_record(
            token_id="t", nonce="n2", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is False
    )
    # the held entry is still present (not evicted): re-presenting n1 is a replay.
    assert (
        store.check_and_record(
            token_id="t", nonce="n1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is False
    )


def test_sqlite_replay_prunes_stale_entries(tmp_path) -> None:
    store = SQLiteReplayStore(_conn(tmp_path / "v.sqlite"))
    old_unix = 1_000_000
    # record an entry whose proof ts is now
    assert (
        store.check_and_record(
            token_id="t", nonce="n1", ts=old_unix, now_unix=old_unix, skew=SKEW
        )
        is True
    )
    # later: now advances past ts + skew, so the old entry is pruned and the same
    # (token_id, nonce) no longer blocks a fresh re-record.
    later_unix = old_unix + SKEW + 1
    assert (
        store.check_and_record(
            token_id="t", nonce="n1", ts=later_unix, now_unix=later_unix, skew=SKEW
        )
        is True
    )


def test_sqlite_schema_records_version_9(tmp_path) -> None:
    conn = _conn(tmp_path / "v.sqlite")
    assert get_sqlite_schema_versions(conn) == (1, 2, 3, 4, 5, 6, 7, 8, 9)
