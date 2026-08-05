from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from idempotency_runtime_fixtures import configured_env
from idempotency_sqlite_fixtures import configured_pool

from vinctor_service.idempotency_models import IdempotencyKeyringConfigError
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.service_config import load_service_runtime_config
from vinctor_service.sqlite import SQLiteV1Service, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


def _seed_active_version(
    database: Path,
    *,
    reserved_slots: int,
    disabled: bool,
) -> dict[str, str]:
    env = configured_env(database)
    config = load_service_runtime_config(env=env)
    keyring = config.idempotency_keyring
    assert keyring is not None
    active = next(
        registration
        for registration in keyring.registrations
        if registration.version == keyring.active_version
    )
    connection = connect_sqlite(database)
    try:
        init_sqlite_schema(connection)
        connection.execute(
            "INSERT INTO idempotency_cipher_key_versions "
            "(version_label, key_commitment, reserved_encryption_slots, "
            "first_seen_epoch, write_disabled_epoch, write_disabled_reason) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                active.version,
                active.commitment,
                reserved_slots,
                1,
                2 if disabled else None,
                "rotation" if disabled else None,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return env


@pytest.mark.parametrize(
    ("reserved_slots", "disabled"),
    ((1, False), (0, True)),
    ids=("slot-count-mismatch", "active-write-disabled"),
)
def test_sqlite_startup_rejects_incompatible_persisted_active_state(
    tmp_path: Path,
    reserved_slots: int,
    disabled: bool,
) -> None:
    database = tmp_path / "startup.sqlite3"
    env = _seed_active_version(
        database,
        reserved_slots=reserved_slots,
        disabled=disabled,
    )
    config = load_service_runtime_config(env=env)
    connection = connect_sqlite(database)
    try:
        with pytest.raises(IdempotencyKeyringConfigError):
            SQLiteV1Service(
                connection,
                idempotency_keyring=config.idempotency_keyring,
            )
    finally:
        connection.close()


def test_sqlite_runtime_readiness_rejects_new_unknown_version_even_if_claimed_expired(
    tmp_path: Path,
) -> None:
    database = tmp_path / "runtime.sqlite3"
    pool = configured_pool(database, size=1)
    observer = connect_sqlite(database)
    try:
        assert pool.is_ready() is True
        observer.execute(
            "INSERT INTO idempotency_cipher_key_versions "
            "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch) "
            "VALUES (?, ?, ?, ?)",
            ("unknown", b"u" * 32, 0, 1),
        )
        observer.execute(
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
                "unknown",
                b"n" * 12,
                b"ciphertext-and-tag",
                0,
                1,
            ),
        )
        observer.commit()

        assert pool.is_ready() is False
    finally:
        observer.close()
        pool.close()


def test_sqlite_runtime_readiness_uses_bounded_counter_snapshot(tmp_path: Path) -> None:
    pool = configured_pool(tmp_path / "bounded.sqlite3", size=1)
    statements: list[str] = []
    try:
        pool._contexts[0].connection.set_trace_callback(statements.append)
        assert pool.is_ready() is True
        assert all(
            "COUNT(*)" not in statement.upper()
            for statement in statements
            if "IDEMPOTENCY_CIPHER_NONCES" in statement.upper()
        )
    finally:
        pool.close()


def test_local_launcher_preserves_default_pool_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Server:
        server_address = ("127.0.0.1", 0)

        def server_close(self) -> None:
            return None

    monkeypatch.setattr(
        "vinctor_service.local_launcher.create_v1_http_server",
        lambda *args, **kwargs: Server(),
    )
    handle = prepare_local_service(
        LocalLaunchConfig(db_path=tmp_path / "local.sqlite3"),
        now=datetime(2026, 7, 20, tzinfo=UTC),
    )
    try:
        assert handle.sqlite_pool is not None
        assert handle.sqlite_pool.size == handle.sqlite_pool.capacity == 8
    finally:
        handle.close()
