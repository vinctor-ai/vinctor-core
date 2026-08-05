from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from vinctor_service.service_config import load_service_runtime_config
from vinctor_service.service_runtime import prepare_service_runtime
from vinctor_service.sqlite import init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


@dataclass(frozen=True, slots=True)
class StartupRejection:
    error_type: str
    error_text: str
    registry_rows: int
    result_rows: int


def _run_startup(database: Path, env: dict[str, str]) -> StartupRejection:
    config = load_service_runtime_config(env={**env, "VINCTOR_PORT": "0"})
    try:
        handle = prepare_service_runtime(config)
    except ValueError as error:
        captured_error = error
    else:
        handle.close()
        pytest.fail("incompatible idempotency startup reached the server bind boundary")
    observer = connect_sqlite(database)
    try:
        registry_row = observer.execute(
            "SELECT COUNT(*) FROM idempotency_cipher_key_versions"
        ).fetchone()
        result_row = observer.execute("SELECT COUNT(*) FROM idempotency_results").fetchone()
        assert registry_row is not None
        assert result_row is not None
        return StartupRejection(
            error_type=type(captured_error).__name__,
            error_text=str(captured_error),
            registry_rows=int(registry_row[0]),
            result_rows=int(result_row[0]),
        )
    finally:
        observer.close()


def exercise_unknown_unexpired_version_startup(
    database: Path,
    env: dict[str, str],
) -> StartupRejection:
    connection = connect_sqlite(database)
    init_sqlite_schema(connection)
    connection.execute(
        "INSERT INTO idempotency_cipher_key_versions "
        "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch) "
        "VALUES (?, ?, ?, ?)",
        ("unknown-historical", b"u" * 32, 0, 1),
    )
    connection.execute(
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
            "unknown-historical",
            b"n" * 12,
            b"ciphertext-and-full-tag",
            1,
            4_102_444_800,
        ),
    )
    connection.commit()
    connection.close()
    return _run_startup(database, env)


def exercise_commitment_mismatch_startup(
    database: Path,
    env: dict[str, str],
) -> StartupRejection:
    connection = connect_sqlite(database)
    init_sqlite_schema(connection)
    connection.execute(
        "INSERT INTO idempotency_cipher_key_versions "
        "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch) "
        "VALUES (?, ?, ?, ?)",
        ("primary", b"m" * 32, 0, 1),
    )
    connection.commit()
    connection.close()
    return _run_startup(database, env)
