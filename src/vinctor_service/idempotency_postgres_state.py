from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager

from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_models import (
    IdempotencyKeyVersionState,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_storage import parse_key_version_state
from vinctor_service.postgres_connection import SerializedPostgresConnection


def register_postgres_keyring(
    conn: SerializedPostgresConnection,
    keyring: IdempotencyKeyring,
    transaction: Callable[[], AbstractContextManager[None]],
) -> None:
    with transaction():
        for registration in keyring.registrations:
            conn.execute(
                """
                INSERT INTO idempotency_cipher_key_versions
                    (version_label, key_commitment,
                     reserved_encryption_slots, first_seen_epoch)
                VALUES (
                    %s, %s, 0,
                    FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT
                )
                ON CONFLICT DO NOTHING
                """,
                (registration.version, registration.commitment),
            )
            row = conn.execute(
                "SELECT key_commitment FROM idempotency_cipher_key_versions "
                "WHERE version_label = %s",
                (registration.version,),
            ).fetchone()
            if row is None or bytes(row[0]) != registration.commitment:
                raise IdempotencyWriteUnavailable


def load_postgres_key_version_state(
    conn: SerializedPostgresConnection,
    version: str,
) -> IdempotencyKeyVersionState:
    row = conn.execute(
        "SELECT reserved_encryption_slots, first_seen_epoch, "
        "soft_limit_reported_epoch, write_disabled_epoch, "
        "write_disabled_reason, drain_completed_epoch, retired_epoch "
        "FROM idempotency_cipher_key_versions WHERE version_label = %s",
        (version,),
    ).fetchone()
    if row is None:
        raise IdempotencyWriteUnavailable
    return parse_key_version_state(version, tuple(row))
