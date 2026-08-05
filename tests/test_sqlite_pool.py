from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest

from vinctor_service.audit_sink import AuditSinks
from vinctor_service.idempotency_keyring import (
    ACTIVE_VERSION_ENV,
    KEYRING_ENV,
    IdempotencyKeyring,
    load_idempotency_keyring,
)
from vinctor_service.idempotency_models import IdempotencyKeyringConfigError
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


def _configured_keyring(material: bytes) -> IdempotencyKeyring:
    encoded = base64.b64encode(material).decode("ascii")
    keyring = load_idempotency_keyring(
        {
            KEYRING_ENV: json.dumps({"primary": encoded}),
            ACTIVE_VERSION_ENV: "primary",
        }
    )
    assert keyring is not None
    return keyring


def test_configured_pool_restart_uses_exact_shared_keyring_for_unexpired_result(
    tmp_path: Path,
) -> None:
    # Given a configured database containing one unexpired encrypted result.
    database = tmp_path / "configured-restart.sqlite"
    keyring = _configured_keyring(b"p" * 32)
    setup = connect_sqlite(database, check_same_thread=False)
    SQLiteV1Service(setup, idempotency_keyring=keyring)
    setup.execute(
        "INSERT INTO idempotency_results "
        "(workspace_id, principal, operation, key_hash, request_fingerprint, "
        "format_version, status_code, cipher_key_version, response_nonce, "
        "response_ciphertext, created_at_epoch, expires_at_epoch) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "ws",
            "agent:a",
            "grant.issue.v1",
            b"k" * 32,
            b"f" * 32,
            1,
            201,
            "primary",
            b"n" * 12,
            b"ciphertext-and-tag",
            1,
            4_000_000_000,
        ),
    )
    setup.commit()
    setup.close()

    # When a configured primary restarts and constructs a size-two production pool.
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=keyring)
    keys = SQLiteLocalKeyRepository(connection)
    pool = SQLiteServicePool(
        database,
        primary_connection=connection,
        primary_service=service,
        primary_key_repository=keys,
        size=2,
    )
    try:
        # Then every service adopts the exact process-shared keyring identity.
        assert all(context.service.idempotency_keyring is keyring for context in pool._contexts)
    finally:
        pool.close()


def test_service_rejects_conflicting_constructor_and_shared_keyrings(
    tmp_path: Path,
) -> None:
    # Given an absent-keyring primary and an explicit configured constructor keyring.
    database = tmp_path / "conflicting-shared-keyring.sqlite"
    primary_connection = connect_sqlite(database)
    primary = SQLiteV1Service(primary_connection)
    secondary_connection = connect_sqlite(database)
    try:
        # When a secondary is constructed from that conflicting process state.
        # Then startup fails instead of registering a key it immediately discards.
        with pytest.raises(IdempotencyKeyringConfigError):
            SQLiteV1Service(
                secondary_connection,
                initialize_schema=False,
                shared_state=primary.shared_state,
                idempotency_keyring=_configured_keyring(b"q" * 32),
            )
    finally:
        secondary_connection.close()
        primary_connection.close()


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
    parsed_sinks: list[AuditSinks] = []

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

    def make_sinks(_env):
        anchor = Anchor()
        export = Export()
        anchors.append(anchor)
        exports.append(export)
        sinks = AuditSinks(anchor=anchor, export=export)
        parsed_sinks.append(sinks)
        return sinks

    monkeypatch.setattr("vinctor_service.sqlite.audit_sinks_from_env", make_sinks)

    pool = _open_pool(tmp_path / "pool.sqlite")
    states = [context.service.shared_state for context in pool._contexts]
    try:
        assert len(anchors) == 1
        assert len(exports) == 1
        assert len(parsed_sinks) == 1
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
