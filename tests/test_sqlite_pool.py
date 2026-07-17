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
