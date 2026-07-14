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
    assert get_sqlite_schema_versions(conn) == tuple(range(1, 14))


# ---- per-token partition (no cross-tenant lockout) -------------------------


def test_sqlite_token_flood_does_not_lock_out_other_token(tmp_path) -> None:
    # Token A floods its own nonces far past its per-token cap of 1; because each
    # flood evicts A's OWN oldest, A's footprint stays at 1 row and never grows
    # toward the generous global backstop. A FRESH proof for a DIFFERENT token B
    # must still be accepted (no cross-token lockout) — this fails under a single
    # global cap, where A's flood would have saturated capacity.
    store = SQLiteReplayStore(
        _conn(tmp_path / "v.sqlite"), max_entries=100, max_per_token=1
    )
    now_unix = 1_000_000
    # A's first nonce -> accepted.
    assert (
        store.check_and_record(
            token_id="A", nonce="a1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is True
    )
    # A floods more distinct nonces: each evicts A's OWN oldest, net-zero global,
    # never touching another token's capacity.
    for i in range(2, 50):
        assert (
            store.check_and_record(
                token_id="A", nonce=f"a{i}", ts=now_unix, now_unix=now_unix, skew=SKEW
            )
            is True
        )
    # A's live footprint never grew past its per-token cap despite the flood.
    a_rows = store._conn.execute(
        "SELECT COUNT(*) FROM pop_replay_nonces WHERE token_id = ?", ("A",)
    ).fetchone()[0]
    assert a_rows == 1
    # A DIFFERENT token B presents a fresh proof -> still accepted.
    assert (
        store.check_and_record(
            token_id="B", nonce="b1", ts=now_unix, now_unix=now_unix, skew=SKEW
        )
        is True
    )


def test_sqlite_per_token_cap_evicts_own_oldest_not_others(tmp_path) -> None:
    # With per-token cap 2: token A holds two nonces; a third nonce for A evicts
    # A's OWN oldest (a1) -- so re-presenting a1 is fresh again -- while B's row
    # is untouched (re-presenting B's nonce is still a replay).
    store = SQLiteReplayStore(
        _conn(tmp_path / "v.sqlite"), max_entries=100, max_per_token=2
    )
    t = 1_000_000
    assert store.check_and_record(
        token_id="A", nonce="a1", ts=t, now_unix=t, skew=SKEW
    ) is True
    assert store.check_and_record(
        token_id="B", nonce="b1", ts=t, now_unix=t, skew=SKEW
    ) is True
    # a2 has a strictly later ts so a1 is unambiguously A's oldest.
    assert store.check_and_record(
        token_id="A", nonce="a2", ts=t + 1, now_unix=t, skew=SKEW
    ) is True
    # A is now at its cap (a1, a2). A third nonce evicts A's oldest (a1).
    assert store.check_and_record(
        token_id="A", nonce="a3", ts=t + 2, now_unix=t, skew=SKEW
    ) is True
    # a1 was evicted -> presenting a1 again is fresh (accepted), evicting a2 now.
    assert store.check_and_record(
        token_id="A", nonce="a1", ts=t + 3, now_unix=t, skew=SKEW
    ) is True
    # B's row was never touched by A's churn: b1 is still a replay.
    assert store.check_and_record(
        token_id="B", nonce="b1", ts=t, now_unix=t, skew=SKEW
    ) is False


def test_sqlite_replay_within_token_still_detected_with_per_token_cap(tmp_path) -> None:
    # Replay detection within a token is unchanged: same (token_id, nonce) -> False.
    store = SQLiteReplayStore(
        _conn(tmp_path / "v.sqlite"), max_entries=100, max_per_token=5
    )
    t = 1_000_000
    assert store.check_and_record(
        token_id="A", nonce="n1", ts=t, now_unix=t, skew=SKEW
    ) is True
    assert store.check_and_record(
        token_id="A", nonce="n1", ts=t, now_unix=t, skew=SKEW
    ) is False
