from __future__ import annotations

import base64
from dataclasses import replace
from typing import Literal, assert_never

import pytest

KEYS_ENV = "VINCTOR_IDEMPOTENCY_KEYRING_JSON"
ACTIVE_ENV = "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION"
TamperKind = Literal["key", "nonce", "aad", "tag", "ciphertext", "version", "envelope"]


def _valid_env() -> dict[str, str]:
    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    return {KEYS_ENV: f'{{"primary":"{encoded}"}}', ACTIVE_ENV: "primary"}


def test_keyring_accepts_only_both_absent_or_a_complete_strict_pair() -> None:
    # Given absent, complete, and one-sided external configurations.
    from vinctor_service.idempotency_keyring import load_idempotency_keyring

    # When the public loader parses each operator environment.
    absent = load_idempotency_keyring({})
    complete = load_idempotency_keyring(_valid_env())

    # Then only both absent or the complete pair succeeds.
    assert absent is None
    assert complete.active_version == "primary"
    with pytest.raises(ValueError):
        load_idempotency_keyring({KEYS_ENV: _valid_env()[KEYS_ENV]})
    with pytest.raises(ValueError):
        load_idempotency_keyring({ACTIVE_ENV: "primary"})


def test_keyring_rejects_duplicate_json_members_invalid_labels_and_duplicate_key_bytes() -> None:
    # Given every malformed JSON, label, base64, length, and active-version class.
    from vinctor_service.idempotency_keyring import (
        IdempotencyKeyringConfigError,
        load_idempotency_keyring,
    )

    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    short = base64.b64encode(b"k" * 31).decode("ascii")
    invalid = (
        {KEYS_ENV: "", ACTIVE_ENV: "primary"},
        {KEYS_ENV: "null", ACTIVE_ENV: "primary"},
        {KEYS_ENV: "[]", ACTIVE_ENV: "primary"},
        {KEYS_ENV: "{}", ACTIVE_ENV: "primary"},
        {KEYS_ENV: f'{{"a":"{encoded}","a":"{encoded}"}}', ACTIVE_ENV: "a"},
        {KEYS_ENV: f'{{"-bad":"{encoded}"}}', ACTIVE_ENV: "-bad"},
        {KEYS_ENV: f'{{"{"a" * 65}":"{encoded}"}}', ACTIVE_ENV: "a" * 65},
        {KEYS_ENV: f'{{"bad label":"{encoded}"}}', ACTIVE_ENV: "bad label"},
        {KEYS_ENV: f'{{"bad/slash":"{encoded}"}}', ACTIVE_ENV: "bad/slash"},
        {KEYS_ENV: '{"a":null}', ACTIVE_ENV: "a"},
        {KEYS_ENV: '{"a":123}', ACTIVE_ENV: "a"},
        {KEYS_ENV: f'{{"a":" {encoded}"}}', ACTIVE_ENV: "a"},
        {KEYS_ENV: f'{{"a":"{encoded}\\n"}}', ACTIVE_ENV: "a"},
        {KEYS_ENV: '{"a":"!!!!"}', ACTIVE_ENV: "a"},
        {KEYS_ENV: f'{{"a":"{short}"}}', ACTIVE_ENV: "a"},
        {KEYS_ENV: f'{{"a":"{encoded}"}}', ACTIVE_ENV: "missing"},
        {KEYS_ENV: f'{{"a":"{encoded}","b":"{encoded}"}}', ACTIVE_ENV: "a"},
        {KEYS_ENV: f'{{"a":"{encoded}"}}', ACTIVE_ENV: "-bad"},
        {KEYS_ENV: f'{{"a":"{encoded}"}}', ACTIVE_ENV: " a"},
    )

    # When each hostile environment reaches the public loader.
    errors: list[str] = []
    for env in invalid:
        with pytest.raises(IdempotencyKeyringConfigError) as captured:
            load_idempotency_keyring(env)
        errors.append(str(captured.value))

    # Then all inputs fail without echoing operator values.
    assert len(errors) == len(invalid)
    assert set(errors) == {"invalid idempotency key configuration"}
    assert all(encoded not in error and short not in error for error in errors)


def test_keyring_repr_and_errors_redact_json_and_key_material(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Given valid key material and an unknown active label.
    from vinctor_service.idempotency_keyring import load_idempotency_keyring

    env = _valid_env()
    raw_json = env[KEYS_ENV]

    # When the valid keyring is represented and invalid input is rejected.
    keyring = load_idempotency_keyring(env)
    with pytest.raises(ValueError) as captured:
        load_idempotency_keyring({KEYS_ENV: raw_json, ACTIVE_ENV: "missing"})

    # Then neither surface contains keyring JSON or key bytes.
    encoded = base64.b64encode(b"k" * 32).decode("ascii")
    assert raw_json not in repr(keyring)
    assert encoded not in repr(keyring)
    assert raw_json not in str(captured.value)
    assert encoded not in str(captured.value)
    assert raw_json not in caplog.text
    assert encoded not in caplog.text


def test_aesgcm_round_trips_arbitrary_response_bytes_with_full_tag() -> None:
    # Given arbitrary non-UTF8 bytes, AES-256 key material, and response AAD.
    from vinctor_service.idempotency_crypto import decrypt_response, encrypt_response

    plaintext = bytes(range(256))
    aad = b"domain-separated-aad"

    # When the public cipher encrypts and decrypts the response.
    envelope = encrypt_response(
        key=b"k" * 32,
        version="primary",
        plaintext=plaintext,
        aad=aad,
    )
    restored = decrypt_response(
        keys={"primary": b"k" * 32},
        envelope=envelope,
        aad=aad,
    )

    # Then exact bytes return and the nonce/tag sizes are the fixed contract.
    assert restored == plaintext
    assert len(envelope.ciphertext) == len(plaintext) + 16
    assert len(envelope.nonce) == 12


@pytest.mark.parametrize(
    "tamper",
    ("key", "nonce", "aad", "tag", "ciphertext", "version", "envelope"),
)
def test_wrong_key_nonce_aad_tag_ciphertext_unknown_version_and_envelope_share_one_error(
    tamper: TamperKind,
) -> None:
    # Given one authentic envelope and a selected tamper class.
    from vinctor_service.idempotency_crypto import (
        IdempotencyCipherUnavailableError,
        decrypt_response,
        encrypt_response,
    )

    aad = b"response-aad"
    envelope = encrypt_response(
        key=b"k" * 32,
        version="primary",
        plaintext=b"credential-bearing-response",
        aad=aad,
    )
    keys = {"primary": b"k" * 32}
    supplied_aad = aad
    match tamper:
        case "key":
            keys = {"primary": b"x" * 32}
        case "nonce":
            envelope = replace(envelope, nonce=b"n" * 12)
        case "aad":
            supplied_aad = b"other-aad"
        case "tag":
            envelope = replace(
                envelope,
                ciphertext=envelope.ciphertext[:-1] + bytes((envelope.ciphertext[-1] ^ 1,)),
            )
        case "ciphertext":
            envelope = replace(
                envelope,
                ciphertext=bytes((envelope.ciphertext[0] ^ 1,)) + envelope.ciphertext[1:],
            )
        case "version":
            envelope = replace(envelope, version="unknown")
        case "envelope":
            envelope = replace(envelope, nonce=b"short")
        case _ as unreachable:
            assert_never(unreachable)

    # When decryption observes the altered input.
    with pytest.raises(IdempotencyCipherUnavailableError) as captured:
        decrypt_response(keys=keys, envelope=envelope, aad=supplied_aad)

    # Then every tamper class exposes one coarse error.
    assert str(captured.value) == "idempotency cipher unavailable"


def test_fingerprint_and_aad_are_domain_separated_and_length_prefixed() -> None:
    # Given the same bytes divided into collision-prone field boundaries.
    from vinctor_service.idempotency_crypto import (
        encode_fingerprint_fields,
        encode_response_aad,
    )

    # When both public codecs encode equal fields and a concatenation collision.
    fingerprint = encode_fingerprint_fields((b"ab", b"c"))
    aad = encode_response_aad((b"ab", b"c"))
    collision = encode_fingerprint_fields((b"a", b"bc"))

    # Then the domain and length prefix both affect exact bytes.
    assert fingerprint != aad
    assert fingerprint != collision


def test_token_response_envelope_contains_no_plaintext_token_or_pop_secret() -> None:
    # Given a serialized token response containing both credentials.
    from vinctor_service.idempotency_crypto import encrypt_response

    token = b"vat_plaintext_probe"
    pop_secret = b"pop_plaintext_probe"
    plaintext = b'{"pop_secret":"' + pop_secret + b'","token":"' + token + b'"}'

    # When the real cipher builds the stored response envelope.
    envelope = encrypt_response(
        key=b"k" * 32,
        version="primary",
        plaintext=plaintext,
        aad=b"token-response-aad",
    )

    # Then persisted nonce/ciphertext bytes contain neither credential.
    stored = envelope.nonce + envelope.ciphertext
    assert token not in stored
    assert pop_secret not in stored
