from __future__ import annotations

import sqlite3
from typing import TYPE_CHECKING, Final

import pytest

if TYPE_CHECKING:
    from vinctor_service.sqlite_txn import SerializedSQLiteConnection

_SQLITE_TEXT_COLUMNS: Final = (
    (
        "idempotency_cipher_key_versions",
        ("version_label", "write_disabled_reason"),
    ),
    (
        "idempotency_cipher_nonces",
        ("cipher_key_version", "workspace_id", "principal", "operation"),
    ),
    (
        "idempotency_results",
        ("workspace_id", "principal", "operation", "cipher_key_version"),
    ),
)

def assert_sqlite_constraints(connection: SerializedSQLiteConnection) -> None:
    for table, columns in _SQLITE_TEXT_COLUMNS:
        row = connection.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        assert row is not None
        definition = " ".join(str(row[0]).lower().split())
        for column in columns:
            assert f"typeof({column}) = 'text'" in definition
    connection.execute(
        "INSERT INTO idempotency_cipher_key_versions "
        "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch) "
        "VALUES (?, ?, ?, ?)",
        ("schema-contract", b"c" * 32, 0, 1),
    )
    connection.commit()
    key_sql = (
        "INSERT INTO idempotency_cipher_key_versions "
        "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch, "
        "write_disabled_epoch, write_disabled_reason) VALUES (?, ?, ?, ?, ?, ?)"
    )
    nonce_sql = (
        "INSERT INTO idempotency_cipher_nonces "
        "(cipher_key_version, slot, nonce, reserved_at_epoch, workspace_id, "
        "principal, operation, key_hash, request_fingerprint) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    result_sql = (
        "INSERT INTO idempotency_results "
        "(workspace_id, principal, operation, key_hash, request_fingerprint, "
        "format_version, status_code, cipher_key_version, response_nonce, "
        "response_ciphertext, created_at_epoch, expires_at_epoch) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    lifecycle_sql = (
        "INSERT INTO idempotency_cipher_key_versions "
        "(version_label, key_commitment, reserved_encryption_slots, first_seen_epoch, "
        "soft_limit_reported_epoch, write_disabled_epoch, write_disabled_reason, "
        "drain_completed_epoch, retired_epoch) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )
    valid_owner = (
        "ws",
        "agent:a",
        "grant.issue.v1",
        b"k" * 32,
        b"f" * 32,
    )
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
    invalid_statements = (
        tuple(
            (key_sql, parameters)
            for parameters in (
                ("duplicate-commitment", b"c" * 32, 0, 1, None, None),
                ("short-commitment", b"short", 0, 1, None, None),
                ("negative-slots", b"d" * 32, -1, 1, None, None),
                ("overflow-slots", b"e" * 32, (2**24) + 1, 1, None, None),
                ("negative-epoch", b"g" * 32, 0, -1, None, None),
                ("invalid-state", b"h" * 32, 0, 1, None, "rotation"),
                (None, b"i" * 32, 0, 1, None, None),
                ("", b"j" * 32, 0, 1, None, None),
                (b"blob-label", b"k" * 32, 0, 1, None, None),
                ("blob-reason", b"l" * 32, 0, 1, 2, b"rotation"),
            )
        )
        + tuple(
            (lifecycle_sql, parameters)
            for parameters in (
                ("text-soft", b"i" * 32, 0, 1, "not-an-epoch", None, None, None, None),
                ("real-soft", b"i" * 32, 0, 1, 2.5, None, None, None, None),
                ("text-write", b"i" * 32, 0, 1, None, "not-an-epoch", "rotation", None, None),
                ("real-write", b"i" * 32, 0, 1, None, 2.5, "rotation", None, None),
                ("text-drain", b"i" * 32, 0, 1, None, 2, "rotation", "not-an-epoch", None),
                ("real-drain", b"i" * 32, 0, 1, None, 2, "rotation", 3.5, None),
                ("text-retired", b"i" * 32, 0, 1, None, 2, "rotation", 3, "not-an-epoch"),
                ("real-retired", b"i" * 32, 0, 1, None, 2, "rotation", 3, 4.5),
                ("missing-reason", b"i" * 32, 0, 1, None, 2, None, None, None),
                ("negative-soft", b"i" * 32, 0, 1, -1, None, None, None, None),
                ("negative-write", b"i" * 32, 0, 1, None, -1, "rotation", None, None),
                ("negative-drain", b"i" * 32, 0, 1, None, 0, "rotation", -1, None),
                ("negative-retired", b"i" * 32, 0, 1, None, 0, "rotation", 0, -1),
            )
        )
        + tuple(
            (nonce_sql, parameters)
            for parameters in (
                ("schema-contract", 1, b"short", 1, *valid_owner),
                ("schema-contract", 2, b"m" * 12, -1, *valid_owner),
                ("schema-contract", 0, b"m" * 12, 1, *valid_owner),
                ("schema-contract", (2**24) + 1, b"m" * 12, 1, *valid_owner),
                ("unknown-version", 1, b"n" * 12, 1, *valid_owner),
                (b"schema-contract", 1, b"o" * 12, 1, *valid_owner),
                ("schema-contract", 1, b"p" * 12, 1, "", *valid_owner[1:]),
                (
                    "schema-contract",
                    1,
                    b"q" * 12,
                    1,
                    valid_owner[0],
                    b"agent:a",
                    *valid_owner[2:],
                ),
                (
                    "schema-contract",
                    1,
                    b"r" * 12,
                    1,
                    *valid_owner[:2],
                    "",
                    *valid_owner[3:],
                ),
                (
                    "schema-contract",
                    1,
                    b"s" * 12,
                    1,
                    *valid_owner[:3],
                    b"short",
                    valid_owner[4],
                ),
                (
                    "schema-contract",
                    1,
                    b"t" * 12,
                    1,
                    *valid_owner[:4],
                    b"short",
                ),
            )
        )
        + tuple(
            (result_sql, parameters)
            for parameters in (
                valid_result[:3] + (b"short",) + valid_result[4:],
                valid_result[:4] + (b"short",) + valid_result[5:],
                valid_result[:5] + (0,) + valid_result[6:],
                valid_result[:5] + (1.5,) + valid_result[6:],
                valid_result[:6] + (99,) + valid_result[7:],
                valid_result[:6] + (200.5,) + valid_result[7:],
                valid_result[:7] + ("unknown-version",) + valid_result[8:],
                valid_result[:8] + (b"short",) + valid_result[9:],
                valid_result[:10] + (-1, 2),
                valid_result[:10] + (2, 1),
                valid_result[:1] + (b"agent:a",) + valid_result[2:],
                valid_result[:2] + (b"grant.issue.v1",) + valid_result[3:],
                valid_result[:7] + (b"schema-contract",) + valid_result[8:],
            )
        )
    )
    for sql, parameters in invalid_statements:
        connection.execute("SAVEPOINT schema_contract")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(sql, parameters)
        connection.execute("ROLLBACK TO schema_contract")
        connection.execute("RELEASE schema_contract")
    valid_nonce = ("schema-contract", 1, b"z" * 12, 1, *valid_owner)
    connection.execute(nonce_sql, valid_nonce)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(nonce_sql, valid_nonce)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(
            nonce_sql,
            ("schema-contract", 1, b"y" * 12, 2, *valid_owner),
        )
    connection.execute(result_sql, valid_result)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(result_sql, valid_result)
    with pytest.raises(sqlite3.IntegrityError):
        connection.execute(result_sql, (b"ws",) + valid_result[1:])
