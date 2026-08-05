from __future__ import annotations

import hashlib
import json
import secrets
from collections.abc import Mapping
from typing import Final, TypeAlias

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vinctor_service.idempotency_models import (
    CryptoReservation,
    EncryptedResponseEnvelope,
    IdempotencyCipherUnavailableError,
    IdempotencyFingerprintError,
    IdempotencyKeyVersion,
    IdempotencyKeyVersionLabel,
    IdempotencyRequestFingerprint,
    RequestFingerprintInput,
    ResponseAadInput,
)

FINGERPRINT_DOMAIN: Final = b"vinctor:idempotency-fingerprint:v1"
RESPONSE_AAD_DOMAIN: Final = b"vinctor:idempotency-response-aad:v1"
ENVELOPE_AAD_DOMAIN: Final = b"vinctor:idempotency-envelope:v1"
ENVELOPE_FORMAT_VERSION: Final = 1
AES_256_KEY_BYTES: Final = 32
GCM_NONCE_BYTES: Final = 12
GCM_TAG_BYTES: Final = 16

_JsonValue: TypeAlias = (
    str | int | float | bool | None | list["_JsonValue"] | dict[str, "_JsonValue"]
)


def canonicalize_request_body(raw_body: bytes) -> bytes:
    if not raw_body:
        return b""
    try:
        parsed: _JsonValue = json.loads(raw_body.decode("utf-8"))
        return json.dumps(
            parsed,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    except (UnicodeDecodeError, ValueError):
        raise IdempotencyFingerprintError from None


def encode_fingerprint_fields(fields: tuple[bytes, ...]) -> bytes:
    return _encode_length_prefixed(FINGERPRINT_DOMAIN, fields)


def build_request_fingerprint(
    request: RequestFingerprintInput,
) -> IdempotencyRequestFingerprint:
    canonical_body = canonicalize_request_body(request.request_body)
    encoded = encode_fingerprint_fields(
        (
            request.method.encode("utf-8"),
            request.path.encode("utf-8"),
            request.authenticated_workspace_id.encode("utf-8"),
            request.authenticated_principal.encode("utf-8"),
            request.operation.encode("utf-8"),
            canonical_body,
        )
    )
    return IdempotencyRequestFingerprint(hashlib.sha256(encoded).digest())


def encode_response_aad(fields: tuple[bytes, ...]) -> bytes:
    return _encode_length_prefixed(RESPONSE_AAD_DOMAIN, fields)


def build_response_aad(metadata: ResponseAadInput) -> bytes:
    if len(metadata.key_hash) != 32 or len(metadata.request_fingerprint) != 32:
        raise IdempotencyCipherUnavailableError
    try:
        return b"".join(
            (
                RESPONSE_AAD_DOMAIN,
                _int64(metadata.format_version),
                _length_prefix(metadata.workspace_id.encode("utf-8")),
                _length_prefix(metadata.principal.encode("utf-8")),
                _length_prefix(metadata.operation.encode("utf-8")),
                _length_prefix(metadata.key_hash),
                _length_prefix(metadata.request_fingerprint),
                _int64(metadata.status_code),
                _length_prefix(metadata.content_type.encode("utf-8")),
                _length_prefix(metadata.cipher_key_version.encode("utf-8")),
                _int64(metadata.created_at_epoch),
                _int64(metadata.expires_at_epoch),
            )
        )
    except OverflowError:
        raise IdempotencyCipherUnavailableError from None


def encrypt_response(
    *,
    key: bytes,
    version: str,
    plaintext: bytes,
    aad: bytes,
) -> EncryptedResponseEnvelope:
    _require_aes256_key(key)
    if not version:
        raise IdempotencyCipherUnavailableError
    try:
        nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    except OSError:
        raise IdempotencyCipherUnavailableError from None
    if len(nonce) != GCM_NONCE_BYTES:
        raise IdempotencyCipherUnavailableError
    return _encrypt_with_nonce(
        key=key,
        version=version,
        nonce=nonce,
        plaintext=plaintext,
        aad=aad,
    )


def encrypt_reserved_response(
    *,
    key: IdempotencyKeyVersion,
    reservation: CryptoReservation,
    plaintext: bytes,
    aad: bytes,
) -> EncryptedResponseEnvelope:
    if key.version != reservation.version:
        raise IdempotencyCipherUnavailableError
    return _encrypt_with_nonce(
        key=key.material,
        version=key.version,
        nonce=reservation.nonce,
        plaintext=plaintext,
        aad=aad,
    )


def decrypt_response(
    *,
    keys: Mapping[str, bytes],
    envelope: EncryptedResponseEnvelope,
    aad: bytes,
) -> bytes:
    if (
        envelope.format_version != ENVELOPE_FORMAT_VERSION
        or not envelope.version
        or len(envelope.nonce) != GCM_NONCE_BYTES
        or len(envelope.ciphertext) < GCM_TAG_BYTES
    ):
        raise IdempotencyCipherUnavailableError
    key = keys.get(envelope.version)
    if key is None:
        raise IdempotencyCipherUnavailableError
    _require_aes256_key(key)
    try:
        return AESGCM(key).decrypt(
            envelope.nonce,
            envelope.ciphertext,
            _envelope_aad(
                format_version=envelope.format_version,
                version=envelope.version,
                aad=aad,
            ),
        )
    except (InvalidTag, OverflowError, ValueError):
        raise IdempotencyCipherUnavailableError from None


def _encode_length_prefixed(
    domain: bytes,
    fields: tuple[bytes, ...],
) -> bytes:
    return domain + b"".join(_length_prefix(field) for field in fields)


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _int64(value: int) -> bytes:
    return value.to_bytes(8, "big", signed=True)


def _envelope_aad(
    *,
    format_version: int,
    version: str,
    aad: bytes,
) -> bytes:
    return b"".join(
        (
            ENVELOPE_AAD_DOMAIN,
            _int64(format_version),
            _length_prefix(version.encode("utf-8")),
            _length_prefix(aad),
        )
    )


def _encrypt_with_nonce(
    *,
    key: bytes,
    version: str,
    nonce: bytes,
    plaintext: bytes,
    aad: bytes,
) -> EncryptedResponseEnvelope:
    _require_aes256_key(key)
    if not version or len(nonce) != GCM_NONCE_BYTES:
        raise IdempotencyCipherUnavailableError
    try:
        ciphertext = AESGCM(key).encrypt(
            nonce,
            plaintext,
            _envelope_aad(
                format_version=ENVELOPE_FORMAT_VERSION,
                version=version,
                aad=aad,
            ),
        )
    except (OverflowError, ValueError):
        raise IdempotencyCipherUnavailableError from None
    return EncryptedResponseEnvelope(
        format_version=ENVELOPE_FORMAT_VERSION,
        version=IdempotencyKeyVersionLabel(version),
        nonce=nonce,
        ciphertext=ciphertext,
    )


def _require_aes256_key(key: bytes) -> None:
    if len(key) != AES_256_KEY_BYTES:
        raise IdempotencyCipherUnavailableError
