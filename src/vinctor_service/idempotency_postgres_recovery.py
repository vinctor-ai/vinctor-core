from __future__ import annotations

import hashlib
from typing import Any, Final

from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_models import (
    IdempotencyInvocation,
    IdempotencyLookupResult,
    IdempotencyResultUnavailable,
)
from vinctor_service.idempotency_storage import (
    CompletedResultRecord,
    classify_completed_result,
)

ADVISORY_LOCK_DOMAIN: Final = b"vinctor:idempotency-advisory-lock:v1"


def signed_advisory_key(
    workspace_id: str,
    principal: str,
    operation: str,
    key_hash: bytes,
) -> int:
    fields = (workspace_id.encode(), principal.encode(), operation.encode(), key_hash)
    encoded = ADVISORY_LOCK_DOMAIN + b"".join(
        len(field).to_bytes(4, "big") + field for field in fields
    )
    return int.from_bytes(hashlib.sha256(encoded).digest()[:8], "big", signed=True)


def lookup_on_current_postgres_connection(
    conn: Any,
    invocation: IdempotencyInvocation,
    keyring: IdempotencyKeyring | None,
    *,
    now_epoch: int,
) -> IdempotencyLookupResult:
    row = conn.execute(
        "SELECT request_fingerprint, format_version, status_code, "
        "cipher_key_version, response_nonce, response_ciphertext, "
        "created_at_epoch, expires_at_epoch FROM idempotency_results "
        "WHERE workspace_id = %s AND principal = %s "
        "AND operation = %s AND key_hash = %s",
        (
            invocation.workspace_id,
            invocation.principal,
            invocation.operation,
            invocation.key_hash,
        ),
    ).fetchone()
    if row is None:
        return classify_completed_result(invocation, None, keyring, now_epoch=now_epoch)
    try:
        record = CompletedResultRecord(
            request_fingerprint=bytes(row[0]),
            format_version=int(row[1]),
            status_code=int(row[2]),
            cipher_key_version=str(row[3]),
            response_nonce=bytes(row[4]),
            response_ciphertext=bytes(row[5]),
            created_at_epoch=int(row[6]),
            expires_at_epoch=int(row[7]),
        )
    except (OverflowError, TypeError, ValueError):
        raise IdempotencyResultUnavailable from None
    return classify_completed_result(invocation, record, keyring, now_epoch=now_epoch)
