from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager

from vinctor_service.idempotency_models import (
    AmbiguousCommitError,
    IdempotencyWriteUnavailable,
)
from vinctor_service.postgres_connection import SerializedPostgresConnection
from vinctor_service.postgres_driver import PostgresError

_WRITE_DISABLE_SQL = (
    "UPDATE idempotency_cipher_key_versions "
    "SET write_disabled_epoch = COALESCE(write_disabled_epoch, %s), "
    "write_disabled_reason = COALESCE(write_disabled_reason, %s) "
    "WHERE version_label = %s AND retired_epoch IS NULL"
)


def complete_postgres_write_disable(
    conn: SerializedPostgresConnection,
    *,
    version: str,
    reason: str,
    now_epoch: int,
    transaction: Callable[[], AbstractContextManager[None]],
) -> None:
    generation = conn.generation
    try:
        try:
            with transaction():
                conn.execute(_WRITE_DISABLE_SQL, (now_epoch, reason, version))
        except AmbiguousCommitError:
            with conn.fresh_authoritative_recovery(after_generation=generation) as authority:
                row = authority.execute(
                    "SELECT write_disabled_epoch, write_disabled_reason "
                    "FROM idempotency_cipher_key_versions WHERE version_label = %s",
                    (version,),
                ).fetchone()
                if row is None:
                    raise IdempotencyWriteUnavailable from None
                if row[0] is not None:
                    if str(row[1]) != reason:
                        raise IdempotencyWriteUnavailable from None
                    return
                authority.execute(_WRITE_DISABLE_SQL, (now_epoch, reason, version))
    except IdempotencyWriteUnavailable:
        raise
    except (PostgresError, RuntimeError):
        raise IdempotencyWriteUnavailable from None
