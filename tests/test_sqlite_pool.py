from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_pool import SQLiteServicePool
from vinctor_service.sqlite_txn import connect_sqlite


def _open_pool(database: Path, *, size: int = 2) -> SQLiteServicePool:
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection)
    keys = SQLiteLocalKeyRepository(connection)
    return SQLiteServicePool(
        database,
        primary_connection=connection,
        primary_service=service,
        primary_key_repository=keys,
        size=size,
    )


def test_pool_leases_distinct_connections_to_concurrent_requests(tmp_path: Path) -> None:
    pool = _open_pool(tmp_path / "pool.sqlite")
    barrier = Barrier(2)
    assert pool.size == 2

    def lease_connection() -> int:
        with pool.request_scope():
            connection = pool.current_context.connection
            assert pool.service.conn is connection
            barrier.wait(timeout=5)
            return id(connection)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            connection_ids = set(executor.map(lambda _: lease_connection(), range(2)))
    finally:
        pool.close()

    assert len(connection_ids) == 2


def test_pool_proxy_requires_a_request_scope(tmp_path: Path) -> None:
    pool = _open_pool(tmp_path / "pool.sqlite", size=1)
    try:
        with pytest.raises(RuntimeError, match="outside a request scope"):
            _ = pool.service.conn
    finally:
        pool.close()


def test_pool_shares_one_process_state_and_closes_export_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    anchors: list[object] = []
    exports: list[object] = []

    class Anchor:
        def emit(self, seq, row_hash, created_at) -> None:
            return None

        def emit_storage_op(self, op, at, head_seq, head_hash) -> None:
            return None

    class Export:
        close_calls = 0

        def emit(self, event) -> None:
            return None

        def close(self) -> None:
            self.close_calls += 1

    def make_anchor(_env):
        anchor = Anchor()
        anchors.append(anchor)
        return anchor

    def make_export(_env):
        export = Export()
        exports.append(export)
        return export

    monkeypatch.setattr("vinctor_service.sqlite.anchor_from_env", make_anchor)
    monkeypatch.setattr("vinctor_service.sqlite.audit_export_from_env", make_export)

    pool = _open_pool(tmp_path / "pool.sqlite")
    states = [context.service.shared_state for context in pool._contexts]
    try:
        assert len(anchors) == 1
        assert len(exports) == 1
        assert all(state is states[0] for state in states)
        assert states[0].audit_anchor is anchors[0]
        assert states[0].audit_export is exports[0]
    finally:
        pool.close()

    assert exports[0].close_calls == 1


def test_pool_rejects_undeclared_service_instance_state(tmp_path: Path) -> None:
    database = tmp_path / "pool.sqlite"
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection)
    keys = SQLiteLocalKeyRepository(connection)
    service._undeclared_cache = {}  # type: ignore[attr-defined]
    try:
        with pytest.raises(RuntimeError, match="_undeclared_cache"):
            SQLiteServicePool(
                database,
                primary_connection=connection,
                primary_service=service,
                primary_key_repository=keys,
                size=2,
            )
    finally:
        connection.close()
