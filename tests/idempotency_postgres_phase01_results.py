from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from vinctor_service.idempotency_crypto import (
    ENVELOPE_FORMAT_VERSION,
    build_response_aad,
    encrypt_reserved_response,
)
from vinctor_service.idempotency_models import ResponseAadInput
from vinctor_service.idempotency_storage import encode_response_plaintext

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CryptoReservation,
        IdempotencyInvocation,
        PreSerializedHttpResponse,
    )
    from vinctor_service.idempotency_postgres import PostgresIdempotencyStore
    from vinctor_service.postgres_connection import SerializedPostgresConnection

CompletedResultFault = Literal[
    "corrupt",
    "expiry_metadata",
    "fingerprint_metadata",
    "unknown_key",
]

@dataclass(frozen=True, slots=True)
class CompletedResultSeed:
    request: IdempotencyInvocation
    response: PreSerializedHttpResponse
    created_at_epoch: int
    expires_at_epoch: int


@dataclass(frozen=True, slots=True)
class PhaseZeroCounts:
    nonces: int
    results: int
    audits: int


def seed_completed_result(
    connection: SerializedPostgresConnection,
    store: PostgresIdempotencyStore,
    seed: CompletedResultSeed,
) -> CryptoReservation:
    reservation = store.reserve_nonce(seed.request, now_epoch=seed.created_at_epoch)
    keyring = store.keyring
    assert keyring is not None
    aad = build_response_aad(
        ResponseAadInput(
            format_version=ENVELOPE_FORMAT_VERSION,
            workspace_id=seed.request.workspace_id,
            principal=seed.request.principal,
            operation=seed.request.operation,
            key_hash=seed.request.key_hash,
            request_fingerprint=seed.request.request_fingerprint,
            status_code=seed.response.status_code,
            content_type=seed.response.content_type,
            cipher_key_version=reservation.version,
            created_at_epoch=seed.created_at_epoch,
            expires_at_epoch=seed.expires_at_epoch,
        )
    )
    envelope = encrypt_reserved_response(
        key=keyring.active_key,
        reservation=reservation,
        plaintext=encode_response_plaintext(seed.response),
        aad=aad,
    )
    connection.execute(
        """
        INSERT INTO idempotency_results (
            workspace_id, principal, operation, key_hash,
            request_fingerprint, format_version, status_code,
            cipher_key_version, response_nonce, response_ciphertext,
            created_at_epoch, expires_at_epoch
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """,
        (
            seed.request.workspace_id,
            seed.request.principal,
            seed.request.operation,
            seed.request.key_hash,
            seed.request.request_fingerprint,
            ENVELOPE_FORMAT_VERSION,
            seed.response.status_code,
            reservation.version,
            reservation.nonce,
            envelope.ciphertext,
            seed.created_at_epoch,
            seed.expires_at_epoch,
        ),
    )
    connection.commit()
    return reservation


def tamper_completed_result(
    connection: SerializedPostgresConnection,
    fault: CompletedResultFault,
) -> None:
    match fault:
        case "corrupt":
            connection.execute(
                "UPDATE idempotency_results SET response_ciphertext = %s",
                (b"x" * 16,),
            )
        case "unknown_key":
            connection.execute(
                "INSERT INTO idempotency_cipher_key_versions "
                "(version_label, key_commitment, reserved_encryption_slots, "
                "first_seen_epoch) VALUES ('unknown', %s, 0, 0)",
                (b"u" * 32,),
            )
            connection.execute("UPDATE idempotency_results SET cipher_key_version = 'unknown'")
        case "expiry_metadata":
            connection.execute(
                "UPDATE idempotency_results "
                "SET created_at_epoch = 0, expires_at_epoch = 1"
            )
        case "fingerprint_metadata":
            connection.execute(
                "UPDATE idempotency_results SET request_fingerprint = %s",
                (b"x" * 32,),
            )
    connection.commit()


def phase_zero_counts(
    connection: SerializedPostgresConnection,
) -> PhaseZeroCounts:
    row = connection.execute(
        "SELECT "
        "(SELECT COUNT(*) FROM idempotency_cipher_nonces), "
        "(SELECT COUNT(*) FROM idempotency_results), "
        "(SELECT COUNT(*) FROM audit_events)"
    ).fetchone()
    assert row is not None
    connection.rollback()
    return PhaseZeroCounts(*(int(value) for value in row))
