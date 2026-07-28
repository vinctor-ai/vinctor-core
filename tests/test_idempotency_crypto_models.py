from __future__ import annotations

import inspect
from dataclasses import replace

import pytest

from vinctor_service import idempotency_crypto
from vinctor_service.idempotency_crypto import (
    build_request_fingerprint,
    build_response_aad,
    canonicalize_request_body,
    decrypt_response,
)
from vinctor_service.idempotency_models import (
    EncryptedResponseEnvelope,
    IdempotencyInvocation,
    IdempotencyKeyVersionLabel,
    IdempotencyResultUnavailable,
    RequestFingerprintInput,
    ResponseAadInput,
)
from vinctor_service.idempotency_storage import (
    CompletedResultRecord,
    classify_completed_result,
)


def test_canonical_request_fingerprint_binds_authenticated_scope_route_and_body() -> None:
    # Given equivalent JSON bodies and server-derived scope and route metadata.
    raw_body = b'{ "ttl_seconds": 60, "scopes": ["read:a", "write:b"] }'
    reordered_body = b'{"scopes":["read:a","write:b"],"ttl_seconds":60}'
    reversed_array_body = b'{"scopes":["write:b","read:a"],"ttl_seconds":60}'
    canonical = canonicalize_request_body(raw_body)
    reordered = canonicalize_request_body(reordered_body)
    reversed_array = canonicalize_request_body(reversed_array_body)
    request = RequestFingerprintInput(
        method="POST",
        path="/v1/grants",
        authenticated_workspace_id="ws_operator",
        authenticated_principal="workspace:ws_operator",
        operation="grant.issue.v1",
        request_body=raw_body,
    )
    expected_fingerprint_hex = "e8e06a99bd4e032da87a9518aae95de4fdad78485182bb8fd0d784ebb2f09182"

    # When each authenticated scope, route, or effective request component changes.
    fingerprint = build_request_fingerprint(request)
    equivalent = build_request_fingerprint(replace(request, request_body=reordered_body))
    changed = (
        replace(request, method="PUT"),
        replace(request, path="/v1/tokens"),
        replace(request, authenticated_workspace_id="ws_other"),
        replace(request, authenticated_principal="agent:agent_release"),
        replace(request, operation="subject_token.mint.v1"),
        replace(request, request_body=reversed_array_body),
    )

    # Then object order and whitespace normalize, while every authoritative field binds.
    assert canonical == reordered
    assert canonical != reversed_array
    assert fingerprint == equivalent
    assert fingerprint.hex() == expected_fingerprint_hex
    assert len(fingerprint) == 32
    assert all(build_request_fingerprint(candidate) != fingerprint for candidate in changed)
    assert b"ws_operator" not in fingerprint
    assert canonicalize_request_body(b"") == b""
    assert canonicalize_request_body(b"{}") != b""


def test_response_aad_binds_row_identity_fingerprint_route_and_response_metadata() -> None:
    # Given one complete persisted-result identity and response metadata record.
    metadata = ResponseAadInput(
        format_version=1,
        workspace_id="ws_operator",
        principal="workspace:ws_operator",
        operation="grant.issue.v1",
        key_hash=b"k" * 32,
        request_fingerprint=b"f" * 32,
        status_code=201,
        content_type="application/json",
        cipher_key_version=IdempotencyKeyVersionLabel("primary"),
        created_at_epoch=1_800_000_000,
        expires_at_epoch=1_800_003_600,
    )
    expected_aad = bytes.fromhex(
        "76696e63746f723a6964656d706f74656e63792d726573706f6e73652d6161643a7631"
        "00000000000000010000000b77735f6f70657261746f7200000015776f726b73706163"
        "653a77735f6f70657261746f720000000e6772616e742e69737375652e763100000020"
        "6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b"
        "000000206666666666666666666666666666666666666666666666666666666666666666"
        "00000000000000c9000000106170706c69636174696f6e2f6a736f6e00000007707269"
        "6d617279000000006b49d200000000006b49e010"
    )

    # When each authenticated row, route, response, key, or time field changes.
    aad = build_response_aad(metadata)
    changed = (
        replace(metadata, format_version=2),
        replace(metadata, workspace_id="ws_other"),
        replace(metadata, principal="agent:agent_release"),
        replace(metadata, operation="subject_token.mint.v1"),
        replace(metadata, key_hash=b"x" * 32),
        replace(metadata, request_fingerprint=b"g" * 32),
        replace(metadata, status_code=403),
        replace(metadata, content_type="application/problem+json"),
        replace(
            metadata,
            cipher_key_version=IdempotencyKeyVersionLabel("historical"),
        ),
        replace(metadata, created_at_epoch=1_800_000_001),
        replace(metadata, expires_at_epoch=1_800_003_601),
    )

    # Then every field is authenticated and identical metadata is deterministic.
    assert aad == build_response_aad(metadata)
    assert aad == expected_aad
    assert all(build_response_aad(candidate) != aad for candidate in changed)


def test_decrypt_response_accepts_independent_aes256_gcm_known_vector() -> None:
    # Given a Node.js-generated AES-256-GCM vector for the versioned envelope AAD.
    envelope = EncryptedResponseEnvelope(
        format_version=1,
        version=IdempotencyKeyVersionLabel("primary"),
        nonce=bytes(12),
        ciphertext=bytes.fromhex("6d738073bb522153528cdb1734f519c4"),
    )

    # When the public decryptor verifies the fixed tag with the selected version.
    plaintext = decrypt_response(
        keys={"primary": bytes(32)},
        envelope=envelope,
        aad=b"",
    )

    # Then the independent empty-plaintext vector authenticates exactly.
    assert plaintext == b""


def test_encrypt_response_generates_one_fresh_96_bit_nonce_inside_each_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a deterministic CSPRNG seam that yields two unique 96-bit nonces.
    generated = iter((b"a" * 12, b"b" * 12))
    requested_sizes: list[int] = []

    def next_nonce(size: int) -> bytes:
        requested_sizes.append(size)
        return next(generated)

    monkeypatch.setattr(idempotency_crypto.secrets, "token_bytes", next_nonce)

    # When two independent response encryptions execute.
    first = idempotency_crypto.encrypt_response(
        key=b"k" * 32,
        version="primary",
        plaintext=b"first",
        aad=b"aad",
    )
    second = idempotency_crypto.encrypt_response(
        key=b"k" * 32,
        version="primary",
        plaintext=b"second",
        aad=b"aad",
    )

    # Then each call owns one 12-byte generation and the API accepts no caller nonce.
    assert requested_sizes == [12, 12]
    assert first.nonce != second.nonce
    assert "nonce" not in inspect.signature(idempotency_crypto.encrypt_response).parameters


def test_expired_leftover_without_historical_key_fails_closed() -> None:
    invocation = IdempotencyInvocation(
        workspace_id="ws_main",
        principal="workspace:ws_main",
        operation="grant.issue.v1",
        key_hash=b"k" * 32,
        request_fingerprint=b"f" * 32,
        max_terminal_ttl_seconds=86_400,
    )
    expired = CompletedResultRecord(
        request_fingerprint=b"f" * 32,
        format_version=1,
        status_code=201,
        cipher_key_version="retired",
        response_nonce=b"n" * 12,
        response_ciphertext=b"unavailable-without-retired-key",
        created_at_epoch=1,
        expires_at_epoch=2,
    )

    with pytest.raises(IdempotencyResultUnavailable):
        classify_completed_result(
            invocation,
            expired,
            None,
            now_epoch=3,
        )
