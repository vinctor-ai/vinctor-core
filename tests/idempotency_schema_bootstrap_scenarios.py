from __future__ import annotations

import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, assert_never

from vinctor_service.idempotency_keyring import (
    ACTIVE_VERSION_ENV,
    KEYRING_ENV,
    IdempotencyKeyring,
    load_idempotency_keyring,
)
from vinctor_service.idempotency_models import IdempotencyKeyringConfigError
from vinctor_service.postgres import (
    PostgresV1Service,
    connect_postgres,
    init_postgres_schema,
)
from vinctor_service.sqlite import SQLiteV1Service, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite

BootstrapConflict = Literal["label", "commitment"]


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    registrations: tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class BootstrapConflictResult:
    error: str | None
    registrations: tuple[str, ...]
    secret_redacted: bool


def _keyring(
    versions: tuple[tuple[str, bytes], ...],
    *,
    active_version: str,
) -> IdempotencyKeyring:
    encoded = {label: base64.b64encode(material).decode("ascii") for label, material in versions}
    keyring = load_idempotency_keyring(
        {
            KEYRING_ENV: json.dumps(encoded, sort_keys=True),
            ACTIVE_VERSION_ENV: active_version,
        }
    )
    assert keyring is not None
    return keyring


def _conflicting_keyring(conflict: BootstrapConflict) -> IdempotencyKeyring:
    match conflict:
        case "label":
            return _keyring(
                (("fresh", b"f" * 32), ("primary", b"q" * 32)),
                active_version="primary",
            )
        case "commitment":
            return _keyring(
                (("fresh", b"f" * 32), ("renamed", b"p" * 32)),
                active_version="fresh",
            )
        case unreachable:
            assert_never(unreachable)


def exercise_sqlite_bootstrap_convergence(database: Path) -> BootstrapResult:
    keyring = _keyring((("primary", b"p" * 32),), active_version="primary")
    setup = connect_sqlite(database)
    init_sqlite_schema(setup)
    setup.close()
    barrier = threading.Barrier(2)

    def bootstrap() -> None:
        connection = connect_sqlite(database)
        try:
            barrier.wait()
            SQLiteV1Service(
                connection,
                initialize_schema=False,
                idempotency_keyring=keyring,
            )
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(bootstrap) for _ in range(2))
        for future in futures:
            future.result()

    observer = connect_sqlite(database)
    try:
        rows = observer.execute(
            "SELECT version_label, reserved_encryption_slots "
            "FROM idempotency_cipher_key_versions ORDER BY version_label"
        ).fetchall()
    finally:
        observer.close()
    return BootstrapResult(tuple((str(row[0]), int(row[1])) for row in rows))


def exercise_sqlite_bootstrap_conflict(
    database: Path,
    conflict: BootstrapConflict,
) -> BootstrapConflictResult:
    original = _keyring((("primary", b"p" * 32),), active_version="primary")
    conflicting = _conflicting_keyring(conflict)
    connection = connect_sqlite(database)
    try:
        SQLiteV1Service(connection, idempotency_keyring=original)
        error: str | None = None
        try:
            SQLiteV1Service(
                connection,
                initialize_schema=False,
                idempotency_keyring=conflicting,
            )
        except IdempotencyKeyringConfigError as exc:
            error = str(exc)
        labels = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT version_label FROM idempotency_cipher_key_versions ORDER BY version_label"
            ).fetchall()
        )
    finally:
        connection.close()
    encoded_secrets = tuple(
        base64.b64encode(material).decode("ascii") for material in (b"p" * 32, b"q" * 32, b"f" * 32)
    )
    return BootstrapConflictResult(
        error=error,
        registrations=labels,
        secret_redacted=error is not None
        and all(secret not in error for secret in encoded_secrets),
    )


def exercise_sqlite_absent_keyring_with_unexpired_result(
    database: Path,
) -> str | None:
    keyring = _keyring((("primary", b"p" * 32),), active_version="primary")
    connection = connect_sqlite(database)
    try:
        SQLiteV1Service(connection, idempotency_keyring=keyring)
        connection.execute(
            "INSERT INTO idempotency_results "
            "(workspace_id, principal, operation, key_hash, request_fingerprint, "
            "format_version, status_code, cipher_key_version, response_nonce, "
            "response_ciphertext, created_at_epoch, expires_at_epoch) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "ws",
                "workspace:ws",
                "grant.issue.v1",
                b"k" * 32,
                b"f" * 32,
                1,
                201,
                "primary",
                b"n" * 12,
                b"ciphertext-tag-only",
                1,
                4_000_000_000,
            ),
        )
        connection.commit()
        try:
            SQLiteV1Service(
                connection,
                initialize_schema=False,
                idempotency_keyring=None,
            )
        except IdempotencyKeyringConfigError as exc:
            return str(exc)
        return None
    finally:
        connection.close()


def exercise_postgres_bootstrap_convergence(dsn: str) -> BootstrapResult:
    keyring = _keyring((("primary", b"p" * 32),), active_version="primary")
    setup = connect_postgres(dsn)
    init_postgres_schema(setup)
    setup.close()
    barrier = threading.Barrier(2)

    def bootstrap() -> None:
        connection = connect_postgres(dsn)
        try:
            barrier.wait()
            PostgresV1Service(
                connection,
                initialize_schema=False,
                idempotency_keyring=keyring,
            )
        finally:
            connection.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(bootstrap) for _ in range(2))
        for future in futures:
            future.result()

    observer = connect_postgres(dsn)
    try:
        rows = observer.execute(
            "SELECT version_label, reserved_encryption_slots "
            "FROM idempotency_cipher_key_versions ORDER BY version_label"
        ).fetchall()
        observer.commit()
    finally:
        observer.close()
    return BootstrapResult(tuple((str(row[0]), int(row[1])) for row in rows))


def exercise_postgres_bootstrap_conflict(
    dsn: str,
    conflict: BootstrapConflict,
) -> BootstrapConflictResult:
    original = _keyring((("primary", b"p" * 32),), active_version="primary")
    conflicting = _conflicting_keyring(conflict)
    connection = connect_postgres(dsn)
    try:
        PostgresV1Service(connection, idempotency_keyring=original)
        error: str | None = None
        try:
            PostgresV1Service(
                connection,
                initialize_schema=False,
                idempotency_keyring=conflicting,
            )
        except IdempotencyKeyringConfigError as exc:
            error = str(exc)
        labels = tuple(
            str(row[0])
            for row in connection.execute(
                "SELECT version_label FROM idempotency_cipher_key_versions ORDER BY version_label"
            ).fetchall()
        )
        connection.commit()
    finally:
        connection.close()
    encoded_secrets = tuple(
        base64.b64encode(material).decode("ascii") for material in (b"p" * 32, b"q" * 32, b"f" * 32)
    )
    return BootstrapConflictResult(
        error=error,
        registrations=labels,
        secret_redacted=error is not None
        and all(secret not in error for secret in encoded_secrets),
    )
