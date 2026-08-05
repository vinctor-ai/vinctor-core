from __future__ import annotations

import base64
import json
import multiprocessing
import os
from multiprocessing.connection import Connection
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from idempotency_http_fixtures import AGENT_HEADERS
from idempotency_http_memory_transport import post_memory_json
from idempotency_sqlite_fixtures import (
    configured_executor,
    count_rows,
    invocation,
    outcome,
)
from idempotency_sqlite_http_scenarios import (
    configured_sqlite_service,
    seed_success_routes,
)

from vinctor_service.idempotency_models import CryptoReservation, IdempotencyWriteUnavailable

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import CacheableTerminalOutcome


def _reserve_then_exit(database: str) -> None:
    connection, store, _ = configured_executor(Path(database))
    store.reserve_nonce(invocation(), now_epoch=100)
    connection.close()
    os._exit(17)


def _encrypt_then_exit(database: str) -> None:
    connection, _, executor = configured_executor(Path(database))
    connection.execute("CREATE TABLE IF NOT EXISTS business_marker(value INTEGER)")
    connection.commit()
    import vinctor_service.idempotency_sqlite as sqlite_idempotency

    def terminate_after_encryption(**_kwargs) -> None:
        os._exit(18)

    sqlite_idempotency.encrypt_response = terminate_after_encryption

    def mutation() -> CacheableTerminalOutcome:
        connection.execute("INSERT INTO business_marker(value) VALUES (1)")
        return outcome()

    executor.execute(invocation(), mutation)


def _hold_old_writer(database: str, ready: Connection) -> None:
    from vinctor_service.idempotency_keyring import load_idempotency_keyring
    from vinctor_service.sqlite import SQLiteV1Service
    from vinctor_service.sqlite_txn import connect_sqlite

    env = _lifecycle_env(database)
    env["VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION"] = "old"
    keyring = load_idempotency_keyring(env)
    assert keyring is not None
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=keyring)
    ready.send(True)
    ready.close()
    multiprocessing.Event().wait()
    service.close()
    connection.close()


def _lifecycle_env(database: str) -> dict[str, str]:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    primary = base64.b64encode(b"p" * 32).decode("ascii")
    return {
        "VINCTOR_DB": database,
        "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (f'{{"old":"{old}","primary":"{primary}"}}'),
        "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "primary",
    }


def test_crash_after_reservation_burns_one_slot_and_retry_uses_new_nonce(
    tmp_path: Path,
) -> None:
    # Given a child process that durably reserves a nonce and exits immediately.
    database = tmp_path / "reservation-crash.sqlite3"
    process = multiprocessing.get_context("spawn").Process(
        target=_reserve_then_exit,
        args=(str(database),),
    )
    process.start()
    process.join(timeout=10)
    # When a fresh process-owned store reserves the retry nonce.
    assert process.exitcode == 17
    connection, store, _ = configured_executor(database)
    try:
        first_nonce = connection.execute(
            "SELECT nonce FROM idempotency_cipher_nonces ORDER BY reserved_at_epoch"
        ).fetchone()[0]
        retry = store.reserve_nonce(invocation(), now_epoch=101)
        # Then the first slot remains burned and the retry uses a different nonce.
        assert count_rows(connection, "idempotency_cipher_nonces") == 2
        assert retry.nonce != first_nonce
    finally:
        connection.close()


def test_crash_after_aes_before_result_commit_burns_nonce_and_rolls_back_business(
    tmp_path: Path,
) -> None:
    # Given a child process terminated after AES but before the outer commit.
    database = tmp_path / "aes-crash.sqlite3"
    process = multiprocessing.get_context("spawn").Process(
        target=_encrypt_then_exit,
        args=(str(database),),
    )
    process.start()
    process.join(timeout=10)
    # When the database is reopened after the forced exit.
    assert process.exitcode == 18
    connection, store, _ = configured_executor(database)
    try:
        # Then the claim survives while business state and result both rolled back.
        assert count_rows(connection, "idempotency_cipher_nonces") == 1
        assert count_rows(connection, "business_marker") == 0
        assert count_rows(connection, "idempotency_results") == 0
        row = connection.execute(
            "SELECT cipher_key_version, slot, nonce, reserved_at_epoch, "
            "claimed_at_epoch FROM idempotency_cipher_nonces"
        ).fetchone()
        assert row is not None and row[4] is not None
        burned = CryptoReservation(str(row[0]), int(row[1]), bytes(row[2]), int(row[3]))
        callback_calls = 0

        def callback() -> CacheableTerminalOutcome:
            nonlocal callback_calls
            callback_calls += 1
            return outcome()

        with pytest.raises(IdempotencyWriteUnavailable):
            store.complete(invocation(), burned, callback)
        fresh = store.reserve_nonce(invocation(), now_epoch=101)
        assert store.complete(invocation(), fresh, callback).body == b'{"ok":true}'
        assert callback_calls == 1
        assert count_rows(connection, "idempotency_cipher_nonces") == 2
        assert count_rows(connection, "idempotency_results") == 1
    finally:
        connection.close()


def test_paused_old_writer_blocks_drain_completion_until_finish_or_termination(
    tmp_path: Path,
) -> None:
    # Given an old-version writer held open in a separate process.
    from vinctor_service.idempotency_lifecycle import IdempotencyLifecycleController

    database = tmp_path / "writer.sqlite3"
    receiving, sending = multiprocessing.get_context("spawn").Pipe(duplex=False)
    process = multiprocessing.get_context("spawn").Process(
        target=_hold_old_writer,
        args=(str(database), sending),
    )
    process.start()
    try:
        assert receiving.recv() is True
        controller = IdempotencyLifecycleController.sqlite(
            database,
            env=_lifecycle_env(str(database)),
        )
        controller.write_disable(version="old", reason="rotation")
        # When drain completion is attempted before and after terminating the writer.
        with pytest.raises(RuntimeError):
            controller.complete_drain(version="old", confirm_no_active_writers=True)
        process.terminate()
        process.join(timeout=10)
        controller.complete_drain(version="old", confirm_no_active_writers=True)
        # Then only the externally drained state can be committed.
        assert controller.status("old").drain_completed_epoch is not None
    finally:
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)


def test_completed_replay_flood_does_not_change_reserved_slot_count(
    tmp_path: Path,
) -> None:
    # Given one completed keyed mutation and its durable reservation.
    connection, _, executor = configured_executor(tmp_path / "flood.sqlite3")
    calls = 0

    def mutation() -> CacheableTerminalOutcome:
        nonlocal calls
        calls += 1
        return outcome()

    try:
        executor.execute(invocation(), mutation)
        before = count_rows(connection, "idempotency_cipher_nonces")
        # When one thousand exact replays are executed.
        for _ in range(1_000):
            assert executor.execute(invocation(), mutation).body == b'{"ok":true}'
        after = count_rows(connection, "idempotency_cipher_nonces")
        # Then neither callback count nor reservation count changes.
        assert (calls, before, after) == (1, 1, 1)
    finally:
        connection.close()


def test_plaintext_scan_finds_no_new_raw_vat_or_serialized_response_copy(
    tmp_path: Path,
) -> None:
    # Given a real keyed token response persisted by SQLite.
    database = tmp_path / "plaintext.sqlite3"
    service, connection = configured_sqlite_service(database)
    seed_success_routes(service)
    try:
        response = post_memory_json(
            service,
            "/v1/tokens",
            {"grant_ref": "grt_seed", "audience": "pep_main", "ttl_seconds": 60},
            {**AGENT_HEADERS, "Idempotency-Key": "token-replay"},
        )
        decoded = json.loads(response.body)
        assert isinstance(decoded, dict)
        token_value = decoded.get("token")
        assert isinstance(token_value, str)
        token = token_value.encode("utf-8")
        dump = "\n".join(connection.iterdump()).encode("utf-8")
    finally:
        connection.close()
    files = tuple(
        path.read_bytes()
        for path in (
            database,
            Path(f"{database}-wal"),
            Path(f"{database}-journal"),
        )
        if path.exists()
    )
    # When the DB, WAL, journal, and logical dump bytes are scanned.
    assert response.status_code == 201
    # Then neither the raw token nor its exact serialized response exists at rest.
    assert all(token not in content for content in (*files, dump))
    assert all(response.body not in content for content in (*files, dump))
