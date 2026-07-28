from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, TypeAlias

from vinctor_service.idempotency_crypto import build_response_aad, decrypt_response
from vinctor_service.idempotency_keyring import IdempotencyKeyring
from vinctor_service.idempotency_models import (
    EncryptedResponseEnvelope,
    HttpResponseObservation,
    IdempotencyConflict,
    IdempotencyInvocation,
    IdempotencyKeyVersionLabel,
    IdempotencyKeyVersionState,
    IdempotencyLookupResult,
    IdempotencyProceedToReservation,
    IdempotencyReplayCandidate,
    IdempotencyResultUnavailable,
    IdempotencyWriteUnavailable,
    PreSerializedHttpResponse,
    ResponseAadInput,
)

JSON_CONTENT_TYPE: Final = "application/json"
RESPONSE_PLAINTEXT_DOMAIN: Final = b"vinctor:idempotency-response-plaintext:v1"
SOFT_SLOT_LIMIT: Final = 2**23
HARD_SLOT_LIMIT: Final = 2**24
NONCE_BYTES: Final = 12
LENGTH_PREFIX_BYTES: Final = 4
KeyStateDbValue: TypeAlias = int | str | None


@dataclass(frozen=True, slots=True, repr=False)
class CompletedResultRecord:
    request_fingerprint: bytes = field(repr=False)
    format_version: int
    status_code: int
    cipher_key_version: str
    response_nonce: bytes = field(repr=False)
    response_ciphertext: bytes = field(repr=False)
    created_at_epoch: int
    expires_at_epoch: int


def encode_response_plaintext(response: PreSerializedHttpResponse) -> bytes:
    return b"".join(
        (
            RESPONSE_PLAINTEXT_DOMAIN,
            _length_prefix(response.body),
            _encode_optional_text(response.observation.error_code),
            _encode_optional_text(response.observation.decision),
        )
    )


def terminal_expiry_epoch(
    invocation: IdempotencyInvocation,
    *,
    now_epoch: int,
    replay_not_after_epoch: int | None,
) -> int:
    ttl_seconds = invocation.max_terminal_ttl_seconds
    if ttl_seconds <= 0:
        ttl_seconds = 86_400
    expires_at_epoch = now_epoch + min(ttl_seconds, 86_400)
    if replay_not_after_epoch is not None:
        expires_at_epoch = min(expires_at_epoch, replay_not_after_epoch)
    return expires_at_epoch


def classify_completed_result(
    invocation: IdempotencyInvocation,
    record: CompletedResultRecord | None,
    keyring: IdempotencyKeyring | None,
    *,
    now_epoch: int,
) -> IdempotencyLookupResult:
    require_invocation(invocation)
    if record is None:
        return IdempotencyProceedToReservation()
    plaintext = authenticate_completed_result(invocation, record, keyring)
    if record.expires_at_epoch <= now_epoch:
        return IdempotencyProceedToReservation()
    if record.request_fingerprint != invocation.request_fingerprint:
        raise IdempotencyConflict
    return IdempotencyReplayCandidate(_decode_response_plaintext(record.status_code, plaintext))


def authenticate_completed_result(
    invocation: IdempotencyInvocation,
    record: CompletedResultRecord,
    keyring: IdempotencyKeyring | None,
) -> bytes:
    require_invocation(invocation)
    if keyring is None:
        raise IdempotencyResultUnavailable
    key = keyring.decryption_key(record.cipher_key_version)
    if key is None:
        raise IdempotencyResultUnavailable
    try:
        aad = build_response_aad(
            ResponseAadInput(
                format_version=record.format_version,
                workspace_id=invocation.workspace_id,
                principal=invocation.principal,
                operation=invocation.operation,
                key_hash=invocation.key_hash,
                request_fingerprint=record.request_fingerprint,
                status_code=record.status_code,
                content_type=JSON_CONTENT_TYPE,
                cipher_key_version=IdempotencyKeyVersionLabel(record.cipher_key_version),
                created_at_epoch=record.created_at_epoch,
                expires_at_epoch=record.expires_at_epoch,
            )
        )
        plaintext = decrypt_response(
            keys={record.cipher_key_version: key.material},
            envelope=EncryptedResponseEnvelope(
                format_version=record.format_version,
                version=IdempotencyKeyVersionLabel(record.cipher_key_version),
                nonce=record.response_nonce,
                ciphertext=record.response_ciphertext,
            ),
            aad=aad,
        )
    except (OverflowError, TypeError, ValueError):
        raise IdempotencyResultUnavailable from None
    return plaintext


def parse_completed_result_row(
    row: Sequence[object],
) -> tuple[IdempotencyInvocation, CompletedResultRecord]:
    match tuple(row):
        case (
            str() as workspace_id,
            str() as principal,
            str() as operation,
            bytes() as key_hash,
            bytes() as request_fingerprint,
            int() as format_version,
            int() as status_code,
            str() as cipher_key_version,
            bytes() as response_nonce,
            bytes() as response_ciphertext,
            int() as created_at_epoch,
            int() as expires_at_epoch,
        ):
            invocation = IdempotencyInvocation(
                workspace_id=workspace_id,
                principal=principal,
                operation=operation,
                key_hash=key_hash,
                request_fingerprint=request_fingerprint,
                max_terminal_ttl_seconds=86_400,
            )
            return invocation, CompletedResultRecord(
                request_fingerprint=request_fingerprint,
                format_version=format_version,
                status_code=status_code,
                cipher_key_version=cipher_key_version,
                response_nonce=response_nonce,
                response_ciphertext=response_ciphertext,
                created_at_epoch=created_at_epoch,
                expires_at_epoch=expires_at_epoch,
            )
        case _:
            raise IdempotencyResultUnavailable


def _decode_response_plaintext(
    status_code: int,
    plaintext: bytes,
) -> PreSerializedHttpResponse:
    if not plaintext.startswith(RESPONSE_PLAINTEXT_DOMAIN):
        raise IdempotencyResultUnavailable
    offset = len(RESPONSE_PLAINTEXT_DOMAIN)
    body, offset = _read_length_prefixed(plaintext, offset)
    error_code, offset = _read_optional_text(plaintext, offset)
    decision, offset = _read_optional_text(plaintext, offset)
    if offset != len(plaintext):
        raise IdempotencyResultUnavailable
    return PreSerializedHttpResponse(
        status_code=status_code,
        content_type=JSON_CONTENT_TYPE,
        body=body,
        observation=HttpResponseObservation(error_code=error_code, decision=decision),
    )


def _read_length_prefixed(payload: bytes, offset: int) -> tuple[bytes, int]:
    length_end = offset + LENGTH_PREFIX_BYTES
    if length_end > len(payload):
        raise IdempotencyResultUnavailable
    value_end = length_end + int.from_bytes(payload[offset:length_end], "big")
    if value_end > len(payload):
        raise IdempotencyResultUnavailable
    return payload[length_end:value_end], value_end


def _read_optional_text(payload: bytes, offset: int) -> tuple[str | None, int]:
    if offset >= len(payload):
        raise IdempotencyResultUnavailable
    match payload[offset]:
        case 0:
            return None, offset + 1
        case 1:
            encoded, next_offset = _read_length_prefixed(payload, offset + 1)
            try:
                return encoded.decode(), next_offset
            except UnicodeDecodeError:
                raise IdempotencyResultUnavailable from None
        case _:
            raise IdempotencyResultUnavailable


def _encode_optional_text(value: str | None) -> bytes:
    if value is None:
        return b"\x00"
    return b"\x01" + _length_prefix(value.encode())


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(LENGTH_PREFIX_BYTES, "big") + value


def parse_key_version_state(
    version: str,
    values: tuple[KeyStateDbValue, ...],
) -> IdempotencyKeyVersionState:
    match values:
        case (
            int() as slots,
            int() as first_seen,
            int() | None as soft,
            int() | None as disabled,
            str() | None as reason,
            int() | None as drained,
            int() | None as retired,
        ):
            return IdempotencyKeyVersionState(
                version=IdempotencyKeyVersionLabel(version),
                reserved_encryption_slots=slots,
                first_seen_epoch=first_seen,
                soft_limit_reported_epoch=soft,
                write_disabled_epoch=disabled,
                write_disabled_reason=reason,
                drain_completed_epoch=drained,
                retired_epoch=retired,
            )
        case _:
            raise IdempotencyResultUnavailable


def require_invocation(invocation: IdempotencyInvocation) -> None:
    if (
        not invocation.workspace_id
        or not invocation.principal
        or not invocation.operation
        or len(invocation.key_hash) != 32
        or len(invocation.request_fingerprint) != 32
    ):
        raise IdempotencyWriteUnavailable
