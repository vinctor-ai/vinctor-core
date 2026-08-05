from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from vinctor_service.postgres_connection import SerializedPostgresConnection

def assert_postgres_constraints(connection: SerializedPostgresConnection) -> None:
    from psycopg import errors

    key_sql = (
        "INSERT INTO idempotency_cipher_key_versions "
        "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch, "
        "write_disabled_epoch, write_disabled_reason) VALUES (%s, %s, %s, %s, %s, %s)"
    )
    nonce_sql = (
        "INSERT INTO idempotency_cipher_nonces "
        "(cipher_key_version, slot, nonce, reserved_at_epoch, workspace_id, "
        "principal, operation, key_hash, request_fingerprint) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    result_sql = (
        "INSERT INTO idempotency_results "
        "(workspace_id, principal, operation, key_hash, request_fingerprint, "
        "format_version, status_code, cipher_key_version, response_nonce, "
        "response_ciphertext, created_at_epoch, expires_at_epoch) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    lifecycle_sql = (
        "INSERT INTO idempotency_cipher_key_versions "
        "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch, "
        "soft_limit_reported_epoch, write_disabled_epoch, write_disabled_reason, "
        "drain_completed_epoch, retired_epoch) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
    )
    valid_owner = (
        "ws",
        "agent:a",
        "grant.issue.v1",
        b"k" * 32,
        b"f" * 32,
    )
    valid_nonce = ("schema-contract", 1, b"z" * 12, 1, *valid_owner)
    valid_result = (
        *valid_owner,
        1,
        201,
        "schema-contract",
        b"z" * 12,
        b"ciphertext-and-tag",
        1,
        2,
    )
    with connection.transaction():
        connection.execute(
            key_sql,
            ("schema-contract", b"c" * 32, 0, 1, None, None),
        )
    with pytest.raises(errors.UniqueViolation), connection.transaction():
        connection.execute(
            key_sql,
            ("duplicate-commitment", b"c" * 32, 0, 1, None, None),
        )
    with pytest.raises(errors.NotNullViolation), connection.transaction():
        connection.execute(key_sql, (None, b"i" * 32, 0, 1, None, None))
    # PostgreSQL assignment casts byte parameters for TEXT columns. Free-text
    # workspace/principal/operation columns therefore cannot enforce the Python
    # source type, while constrained labels/reasons and foreign keys still reject it.
    with pytest.raises(errors.CheckViolation), connection.transaction():
        connection.execute(
            key_sql,
            (b"blob-label", b"i" * 32, 0, 1, None, None),
        )
    with pytest.raises(errors.CheckViolation), connection.transaction():
        connection.execute(
            key_sql,
            ("blob-reason", b"i" * 32, 0, 1, 2, b"rotation"),
        )
    for parameters in (
        ("", b"i" * 32, 0, 1, None, None),
        ("short-commitment", b"short", 0, 1, None, None),
        ("negative-slots", b"d" * 32, -1, 1, None, None),
        ("overflow-slots", b"e" * 32, (2**24) + 1, 1, None, None),
        ("negative-epoch", b"g" * 32, 0, -1, None, None),
        ("invalid-state", b"h" * 32, 0, 1, None, "rotation"),
    ):
        with pytest.raises(errors.CheckViolation), connection.transaction():
            connection.execute(key_sql, parameters)
    for parameters in (
        ("text-soft", b"i" * 32, 0, 1, "not-an-epoch", None, None, None, None),
        ("text-write", b"i" * 32, 0, 1, None, "not-an-epoch", "rotation", None, None),
        (
            "text-drain",
            b"i" * 32,
            0,
            1,
            None,
            2,
            "rotation",
            "not-an-epoch",
            None,
        ),
        (
            "text-retired",
            b"i" * 32,
            0,
            1,
            None,
            2,
            "rotation",
            3,
            "not-an-epoch",
        ),
    ):
        with pytest.raises(errors.InvalidTextRepresentation), connection.transaction():
            connection.execute(lifecycle_sql, parameters)
    for parameters in (
        ("missing-reason", b"i" * 32, 0, 1, None, 2, None, None, None),
        ("negative-soft", b"i" * 32, 0, 1, -1, None, None, None, None),
        ("negative-write", b"i" * 32, 0, 1, None, -1, "rotation", None, None),
        ("negative-drain", b"i" * 32, 0, 1, None, 0, "rotation", -1, None),
        ("negative-retired", b"i" * 32, 0, 1, None, 0, "rotation", 0, -1),
    ):
        with pytest.raises(errors.CheckViolation), connection.transaction():
            connection.execute(lifecycle_sql, parameters)
    for parameters in (
        ("schema-contract", 1, b"short", 1, *valid_owner),
        ("schema-contract", 2, b"m" * 12, -1, *valid_owner),
        ("schema-contract", 0, b"m" * 12, 1, *valid_owner),
        ("schema-contract", (2**24) + 1, b"m" * 12, 1, *valid_owner),
        ("schema-contract", 2, b"s" * 12, 1, "", *valid_owner[1:]),
        (
            "schema-contract",
            2,
            b"t" * 12,
            1,
            *valid_owner[:3],
            b"short",
            valid_owner[4],
        ),
        (
            "schema-contract",
            2,
            b"u" * 12,
            1,
            *valid_owner[:4],
            b"short",
        ),
    ):
        with pytest.raises(errors.CheckViolation), connection.transaction():
            connection.execute(nonce_sql, parameters)
    with pytest.raises(errors.ForeignKeyViolation), connection.transaction():
        connection.execute(
            nonce_sql,
            ("unknown-version", 1, b"n" * 12, 1, *valid_owner),
        )
    with pytest.raises(errors.ForeignKeyViolation), connection.transaction():
        connection.execute(
            nonce_sql,
            (b"schema-contract", 1, b"o" * 12, 1, *valid_owner),
        )
    with connection.transaction():
        connection.execute(nonce_sql, valid_nonce)
    with pytest.raises(errors.UniqueViolation), connection.transaction():
        connection.execute(nonce_sql, valid_nonce)
    with pytest.raises(errors.UniqueViolation), connection.transaction():
        connection.execute(
            nonce_sql,
            ("schema-contract", 1, b"y" * 12, 2, *valid_owner),
        )
    for parameters in (
        valid_result[:3] + (b"short",) + valid_result[4:],
        valid_result[:4] + (b"short",) + valid_result[5:],
        valid_result[:5] + (0,) + valid_result[6:],
        valid_result[:6] + (99,) + valid_result[7:],
        valid_result[:8] + (b"short",) + valid_result[9:],
        valid_result[:10] + (-1, 2),
        valid_result[:10] + (2, 1),
    ):
        with pytest.raises(errors.CheckViolation), connection.transaction():
            connection.execute(result_sql, parameters)
    with pytest.raises(errors.ForeignKeyViolation), connection.transaction():
        connection.execute(
            result_sql,
            valid_result[:7] + ("unknown-version",) + valid_result[8:],
        )
    with pytest.raises(errors.ForeignKeyViolation), connection.transaction():
        connection.execute(
            result_sql,
            valid_result[:7] + (b"schema-contract",) + valid_result[8:],
        )
    with connection.transaction():
        connection.execute(result_sql, valid_result)
    with pytest.raises(errors.UniqueViolation), connection.transaction():
        connection.execute(result_sql, valid_result)
