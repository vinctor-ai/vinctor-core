from __future__ import annotations

from typing import TYPE_CHECKING

from vinctor_service.idempotency_models import (
    CacheableTerminalOutcome,
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyInvocation,
    IdempotencyWriteUnavailable,
)
from vinctor_service.idempotency_storage import CompletedResultRecord
from vinctor_service.postgres_connection import SerializedPostgresConnection

if TYPE_CHECKING:
    from vinctor_service.idempotency_postgres_completion import PostgresCompletionAttempt


def require_postgres_reservation_authentic(
    conn: SerializedPostgresConnection,
    invocation: IdempotencyInvocation,
    reservation: CryptoReservation,
) -> int | None:
    row = conn.execute(
        "SELECT versions.write_disabled_epoch, versions.retired_epoch, "
        "nonces.claimed_at_epoch "
        "FROM idempotency_cipher_nonces AS nonces "
        "JOIN idempotency_cipher_key_versions AS versions "
        "ON versions.version_label = nonces.cipher_key_version "
        "WHERE nonces.cipher_key_version = %s AND nonces.slot = %s "
        "AND nonces.nonce = %s AND nonces.reserved_at_epoch = %s "
        "AND nonces.workspace_id = %s AND nonces.principal = %s "
        "AND nonces.operation = %s AND nonces.key_hash = %s "
        "AND nonces.request_fingerprint = %s",
        reservation.ledger_identity + invocation.reservation_owner_identity,
    ).fetchone()
    if row is None or row[0] is not None or row[1] is not None:
        raise IdempotencyWriteUnavailable
    return None if row[2] is None else int(row[2])


def postgres_database_epoch(conn: SerializedPostgresConnection) -> int:
    row = conn.execute("SELECT FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT").fetchone()
    if row is None:
        raise IdempotencyWriteUnavailable
    return int(row[0])


def postgres_result_uses_reservation_nonce(
    conn: SerializedPostgresConnection,
    reservation: CryptoReservation,
) -> bool:
    row = conn.execute(
        "SELECT 1 FROM idempotency_results "
        "WHERE cipher_key_version = %s AND response_nonce = %s LIMIT 1",
        (reservation.version, reservation.nonce),
    ).fetchone()
    return row is not None


def claim_postgres_reservation(
    conn: SerializedPostgresConnection,
    invocation: IdempotencyInvocation,
    reservation: CryptoReservation,
    *,
    now_epoch: int,
) -> None:
    cursor = conn.execute(
        "UPDATE idempotency_cipher_nonces AS nonces SET claimed_at_epoch = %s "
        "FROM idempotency_cipher_key_versions AS versions "
        "WHERE versions.version_label = nonces.cipher_key_version "
        "AND versions.write_disabled_epoch IS NULL AND versions.retired_epoch IS NULL "
        "AND nonces.cipher_key_version = %s AND nonces.slot = %s "
        "AND nonces.nonce = %s AND nonces.reserved_at_epoch = %s "
        "AND nonces.workspace_id = %s AND nonces.principal = %s "
        "AND nonces.operation = %s AND nonces.key_hash = %s "
        "AND nonces.request_fingerprint = %s AND nonces.claimed_at_epoch IS NULL "
        "AND NOT EXISTS ("
        "SELECT 1 FROM idempotency_results AS results "
        "WHERE results.cipher_key_version = nonces.cipher_key_version "
        "AND results.response_nonce = nonces.nonce"
        ")",
        (
            now_epoch,
            *reservation.ledger_identity,
            *invocation.reservation_owner_identity,
        ),
    )
    if cursor.rowcount != 1:
        raise IdempotencyWriteUnavailable


def load_postgres_result(
    conn: SerializedPostgresConnection,
    invocation: IdempotencyInvocation,
) -> CompletedResultRecord | None:
    row = conn.execute(
        "SELECT request_fingerprint, format_version, status_code, "
        "cipher_key_version, response_nonce, response_ciphertext, "
        "created_at_epoch, expires_at_epoch FROM idempotency_results "
        "WHERE workspace_id = %s AND principal = %s "
        "AND operation = %s AND key_hash = %s",
        invocation.result_identity,
    ).fetchone()
    if row is None:
        return None
    return CompletedResultRecord(
        request_fingerprint=bytes(row[0]),
        format_version=int(row[1]),
        status_code=int(row[2]),
        cipher_key_version=str(row[3]),
        response_nonce=bytes(row[4]),
        response_ciphertext=bytes(row[5]),
        created_at_epoch=int(row[6]),
        expires_at_epoch=int(row[7]),
    )


def delete_postgres_result(
    conn: SerializedPostgresConnection,
    invocation: IdempotencyInvocation,
) -> None:
    conn.execute(
        "DELETE FROM idempotency_results "
        "WHERE workspace_id = %s AND principal = %s "
        "AND operation = %s AND key_hash = %s",
        invocation.result_identity,
    )


def insert_postgres_result(
    conn: SerializedPostgresConnection,
    attempt: PostgresCompletionAttempt,
    outcome: CacheableTerminalOutcome,
    envelope: EncryptedResponseEnvelope,
    *,
    now_epoch: int,
    expires_at_epoch: int,
) -> None:
    conn.execute(
        "INSERT INTO idempotency_results "
        "(workspace_id, principal, operation, key_hash, request_fingerprint, "
        "format_version, status_code, cipher_key_version, response_nonce, "
        "response_ciphertext, created_at_epoch, expires_at_epoch) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (
            attempt.invocation.workspace_id,
            attempt.invocation.principal,
            attempt.invocation.operation,
            attempt.invocation.key_hash,
            attempt.invocation.request_fingerprint,
            envelope.format_version,
            outcome.response.status_code,
            envelope.version,
            envelope.nonce,
            envelope.ciphertext,
            now_epoch,
            expires_at_epoch,
        ),
    )
