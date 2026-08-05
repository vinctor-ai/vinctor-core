from __future__ import annotations

from typing import TYPE_CHECKING

from idempotency_sqlite_fixtures import (
    invocation,
    outcome,
)
from idempotency_sqlite_store_models import CompletedResultSeed

from vinctor_service.idempotency_crypto import (
    ENVELOPE_FORMAT_VERSION,
    build_response_aad,
    encrypt_reserved_response,
)
from vinctor_service.idempotency_models import (
    ResponseAadInput,
)
from vinctor_service.idempotency_storage import encode_response_plaintext

if TYPE_CHECKING:
    from vinctor_service.idempotency_models import (
        CacheableTerminalOutcome,
        IdempotencyInvocation,
    )
    from vinctor_service.idempotency_sqlite import SQLiteIdempotencyStore
    from vinctor_service.sqlite_txn import SerializedSQLiteConnection

def _seed_completed_result(
    connection: SerializedSQLiteConnection,
    store: SQLiteIdempotencyStore,
    seed: CompletedResultSeed | None = None,
    *,
    request: IdempotencyInvocation | None = None,
) -> tuple[IdempotencyInvocation, CacheableTerminalOutcome]:
    request = invocation() if request is None else request
    if seed is None:
        seed = CompletedResultSeed(outcome(), store.database_epoch())
    reservation = store.reserve_nonce(request, now_epoch=seed.created_at_epoch)
    keyring = store.keyring
    assert keyring is not None
    expires_at_epoch = seed.created_at_epoch + request.max_terminal_ttl_seconds
    aad = build_response_aad(
        ResponseAadInput(
            format_version=ENVELOPE_FORMAT_VERSION,
            workspace_id=request.workspace_id,
            principal=request.principal,
            operation=request.operation,
            key_hash=request.key_hash,
            request_fingerprint=request.request_fingerprint,
            status_code=seed.terminal.response.status_code,
            content_type=seed.terminal.response.content_type,
            cipher_key_version=reservation.version,
            created_at_epoch=seed.created_at_epoch,
            expires_at_epoch=expires_at_epoch,
        )
    )
    envelope = encrypt_reserved_response(
        key=keyring.active_key,
        reservation=reservation,
        plaintext=encode_response_plaintext(seed.terminal.response),
        aad=aad,
    )
    connection.execute(
        """
        INSERT INTO idempotency_results (
            workspace_id, principal, operation, key_hash,
            request_fingerprint, format_version, status_code,
            cipher_key_version, response_nonce, response_ciphertext,
            created_at_epoch, expires_at_epoch
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            request.workspace_id,
            request.principal,
            request.operation,
            request.key_hash,
            request.request_fingerprint,
            ENVELOPE_FORMAT_VERSION,
            seed.terminal.response.status_code,
            reservation.version,
            reservation.nonce,
            envelope.ciphertext,
            seed.created_at_epoch,
            expires_at_epoch,
        ),
    )
    connection.commit()
    return request, seed.terminal
