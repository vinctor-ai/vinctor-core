from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Literal, TypeAlias

IDEMPOTENCY_TABLES: Final = (
    "idempotency_cipher_key_versions",
    "idempotency_cipher_nonces",
    "idempotency_results",
)
ColumnStorage: TypeAlias = Literal["bytes", "integer", "text"]
DECLARED_COLUMN_STORAGE: Final[dict[str, ColumnStorage]] = {
    "bigint": "integer",
    "blob": "bytes",
    "bytea": "bytes",
    "integer": "integer",
    "smallint": "integer",
    "text": "text",
}


@dataclass(frozen=True, slots=True)
class ColumnShape:
    name: str
    storage: ColumnStorage
    nullable: bool
    default: str | None


EXPECTED_COLUMN_SHAPES: Final = (
    (
        "idempotency_cipher_key_versions",
        (
            ColumnShape("version_label", "text", False, None),
            ColumnShape("key_commitment", "bytes", False, None),
            ColumnShape("reserved_encryption_slots", "integer", False, None),
            ColumnShape("first_seen_epoch", "integer", False, None),
            ColumnShape("soft_limit_reported_epoch", "integer", True, None),
            ColumnShape("write_disabled_epoch", "integer", True, None),
            ColumnShape("write_disabled_reason", "text", True, None),
            ColumnShape("drain_completed_epoch", "integer", True, None),
            ColumnShape("retired_epoch", "integer", True, None),
        ),
    ),
    (
        "idempotency_cipher_nonces",
        (
            ColumnShape("cipher_key_version", "text", False, None),
            ColumnShape("slot", "integer", False, None),
            ColumnShape("nonce", "bytes", False, None),
            ColumnShape("reserved_at_epoch", "integer", False, None),
            ColumnShape("workspace_id", "text", False, None),
            ColumnShape("principal", "text", False, None),
            ColumnShape("operation", "text", False, None),
            ColumnShape("key_hash", "bytes", False, None),
            ColumnShape("request_fingerprint", "bytes", False, None),
            ColumnShape("claimed_at_epoch", "integer", True, None),
        ),
    ),
    (
        "idempotency_results",
        (
            ColumnShape("workspace_id", "text", False, None),
            ColumnShape("principal", "text", False, None),
            ColumnShape("operation", "text", False, None),
            ColumnShape("key_hash", "bytes", False, None),
            ColumnShape("request_fingerprint", "bytes", False, None),
            ColumnShape("format_version", "integer", False, None),
            ColumnShape("status_code", "integer", False, None),
            ColumnShape("cipher_key_version", "text", False, None),
            ColumnShape("response_nonce", "bytes", False, None),
            ColumnShape("response_ciphertext", "bytes", False, None),
            ColumnShape("created_at_epoch", "integer", False, None),
            ColumnShape("expires_at_epoch", "integer", False, None),
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class SchemaShape:
    tables: tuple[str, ...]
    columns: tuple[tuple[str, tuple[ColumnShape, ...]], ...]
    indexes: tuple[tuple[str, bool, tuple[str, ...]], ...]
    foreign_keys: tuple[tuple[str, str, str, str], ...]
    checks: tuple[tuple[str, str], ...]


def assert_schema_shape(shape: SchemaShape) -> None:
    assert shape.tables == tuple(sorted(IDEMPOTENCY_TABLES))
    assert shape.columns == tuple(sorted(EXPECTED_COLUMN_SHAPES))
    assert (
        "idempotency_cipher_key_versions",
        True,
        ("version_label",),
    ) in shape.indexes
    assert (
        "idempotency_cipher_key_versions",
        True,
        ("key_commitment",),
    ) in shape.indexes
    assert (
        "idempotency_cipher_nonces",
        True,
        ("cipher_key_version", "nonce"),
    ) in shape.indexes
    assert (
        "idempotency_cipher_nonces",
        True,
        ("cipher_key_version", "slot"),
    ) in shape.indexes
    assert (
        "idempotency_results",
        True,
        ("workspace_id", "principal", "operation", "key_hash"),
    ) in shape.indexes
    assert (
        "idempotency_results",
        True,
        ("cipher_key_version", "response_nonce"),
    ) in shape.indexes
    assert (
        "idempotency_results",
        False,
        ("expires_at_epoch",),
    ) in shape.indexes
    foreign_key_text = " ".join(" ".join(parts).lower() for parts in shape.foreign_keys)
    assert "idempotency_cipher_nonces" in foreign_key_text
    assert "idempotency_results" in foreign_key_text
    assert foreign_key_text.count("idempotency_cipher_key_versions") == 2
    check_text = " ".join(definition for _, definition in shape.checks)
    for required in (
        "reserved_encryption_slots",
        "first_seen_epoch",
        "write_disabled_epoch",
        "write_disabled_reason",
        "slot",
        "nonce",
        "reserved_at_epoch",
        "key_hash",
        "request_fingerprint",
        "claimed_at_epoch",
        "format_version",
        "status_code",
        "response_nonce",
        "created_at_epoch",
        "expires_at_epoch",
    ):
        assert required in check_text
