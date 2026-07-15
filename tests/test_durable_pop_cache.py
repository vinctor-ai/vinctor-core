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
from vinctor_service.sqlite_txn import connect_sqlite

SKEW = 60


def _conn(path) -> sqlite3.Connection:
    conn = connect_sqlite(path)
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
    assert get_sqlite_schema_versions(conn) == tuple(range(1, 15))


# ---- per-token partition (no cross-tenant lockout) -------------------------


def test_sqlite_token_flood_does_not_lock_out_other_token(tmp_path) -> None:
    # Token A floods its own nonces far past its per-token cap of 1; beyond the
    # cap each flood attempt is REJECTED (fail closed), so A's footprint stays
    # at 1 row and never grows toward the generous global backstop. A FRESH
    # proof for a DIFFERENT token B must still be accepted (no cross-token
    # lockout) — this fails under a single global cap, where A's flood would
    # have saturated capacity.
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
    # A floods more distinct nonces: each is rejected at A's own cap, never
    # evicting a1 and never touching another token's capacity.
    for i in range(2, 50):
        assert (
            store.check_and_record(
                token_id="A", nonce=f"a{i}", ts=now_unix, now_unix=now_unix, skew=SKEW
            )
            is False
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


def test_sqlite_flood_cannot_evict_fresh_nonce_for_replay(tmp_path) -> None:
    # SECURITY (ADR 0007): never evict a still-fresh nonce to make room. An
    # attacker who captured a valid proof must not be able to flood the same
    # token's cap with fresh nonces to push the captured nonce out and replay
    # it inside the freshness window.
    cap = 4
    store = SQLiteReplayStore(
        _conn(tmp_path / "v.sqlite"), max_entries=100, max_per_token=cap
    )
    now_unix = 1_000_000
    # The captured proof's nonce: oldest ts in the window (still fresh).
    assert store.check_and_record(
        token_id="A", nonce="n1", ts=now_unix - 1, now_unix=now_unix, skew=SKEW
    ) is True
    # Attacker pushes `cap` more distinct fresh nonces for the SAME token.
    for i in range(cap):
        store.check_and_record(
            token_id="A", nonce=f"flood{i}", ts=now_unix, now_unix=now_unix,
            skew=SKEW,
        )
    # Re-presenting the captured nonce within the window MUST still be a
    # replay: n1 was never evicted to make room for the flood.
    assert store.check_and_record(
        token_id="A", nonce="n1", ts=now_unix - 1, now_unix=now_unix, skew=SKEW
    ) is False


def test_sqlite_per_token_cap_full_of_fresh_fails_closed(tmp_path) -> None:
    # When a token's cap is full of still-fresh nonces, a brand-new nonce is
    # rejected (fail closed) — nothing is evicted, and other tokens are
    # unaffected. Operators can raise the cap; correctness never depends on
    # evicting a live nonce.
    store = SQLiteReplayStore(
        _conn(tmp_path / "v.sqlite"), max_entries=100, max_per_token=2
    )
    t = 1_000_000
    assert store.check_and_record(
        token_id="A", nonce="a1", ts=t, now_unix=t, skew=SKEW
    ) is True
    assert store.check_and_record(
        token_id="A", nonce="a2", ts=t + 1, now_unix=t, skew=SKEW
    ) is True
    # A's cap is full of fresh nonces -> a3 rejected (fail closed).
    assert store.check_and_record(
        token_id="A", nonce="a3", ts=t + 2, now_unix=t, skew=SKEW
    ) is False
    # Nothing was evicted: both held nonces are still replays.
    assert store.check_and_record(
        token_id="A", nonce="a1", ts=t, now_unix=t, skew=SKEW
    ) is False
    assert store.check_and_record(
        token_id="A", nonce="a2", ts=t + 1, now_unix=t, skew=SKEW
    ) is False
    # A different token is unaffected by A's full cap.
    assert store.check_and_record(
        token_id="B", nonce="b1", ts=t, now_unix=t, skew=SKEW
    ) is True


def test_sqlite_expired_entries_still_purged_at_cap(tmp_path) -> None:
    # Fail-closed applies only to FRESH entries: once a window passes, expired
    # rows are purged, so the store stays bounded across windows and the token
    # is not locked out forever.
    store = SQLiteReplayStore(
        _conn(tmp_path / "v.sqlite"), max_entries=100, max_per_token=2
    )
    t0 = 1_000_000
    assert store.check_and_record(
        token_id="A", nonce="a1", ts=t0, now_unix=t0, skew=SKEW
    ) is True
    assert store.check_and_record(
        token_id="A", nonce="a2", ts=t0, now_unix=t0, skew=SKEW
    ) is True
    # Next window: the t0 rows are expired -> purged, so a new nonce is
    # accepted (no permanent lockout) and the footprint stays bounded.
    t1 = t0 + SKEW + 1
    assert store.check_and_record(
        token_id="A", nonce="a3", ts=t1, now_unix=t1, skew=SKEW
    ) is True
    total = store._conn.execute(
        "SELECT COUNT(*) FROM pop_replay_nonces"
    ).fetchone()[0]
    assert total == 1


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
