from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, TypeAlias, assert_never

from vinctor_service.idempotency_models import (
    IdempotencyKeyCommitment,
    IdempotencyKeyRegistration,
    IdempotencyKeyringConfigError,
    IdempotencyKeyVersion,
    IdempotencyKeyVersionLabel,
)

KEYRING_ENV: Final = "VINCTOR_IDEMPOTENCY_KEYRING_JSON"
ACTIVE_VERSION_ENV: Final = "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION"
KEY_COMMITMENT_DOMAIN: Final = b"vinctor.idempotency.key-commitment.v1\x00"
_VERSION_LABEL: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_AES_256_KEY_BYTES: Final = 32


@dataclass(frozen=True, slots=True)
class _JsonObject:
    pairs: tuple[tuple[str, str], ...]


_JsonValue: TypeAlias = str | int | float | bool | None | list["_JsonValue"] | _JsonObject


@dataclass(frozen=True, slots=True, repr=False)
class IdempotencyKeyring:
    _active_key: IdempotencyKeyVersion = field(repr=False)
    _decryption_keys: tuple[IdempotencyKeyVersion, ...] = field(repr=False)

    @property
    def active_version(self) -> IdempotencyKeyVersionLabel:
        return self._active_key.version

    @property
    def active_key(self) -> IdempotencyKeyVersion:
        return self._active_key

    @property
    def version_labels(self) -> tuple[IdempotencyKeyVersionLabel, ...]:
        return tuple(key.version for key in self._decryption_keys)

    @property
    def registrations(self) -> tuple[IdempotencyKeyRegistration, ...]:
        return tuple(
            IdempotencyKeyRegistration(
                version=key.version,
                commitment=key.commitment,
            )
            for key in self._decryption_keys
        )

    def decryption_key(self, version: str) -> IdempotencyKeyVersion | None:
        return next(
            (key for key in self._decryption_keys if key.version == version),
            None,
        )

    def __repr__(self) -> str:
        return (
            "IdempotencyKeyring("
            f"active_version={self.active_version!r}, "
            f"version_count={len(self._decryption_keys)}"
            ")"
        )


@dataclass(frozen=True, slots=True)
class KeyVersionReadinessState:
    version: str
    write_disabled: bool
    retired: bool
    reserved_encryption_slots: int
    nonce_count: int


def idempotency_readiness(
    *,
    configured_versions: set[str],
    unexpired_versions: set[str],
    active_version: str | None,
    key_versions: tuple[KeyVersionReadinessState, ...] = (),
    allow_active_write_disabled: bool = False,
) -> bool:
    if not unexpired_versions.issubset(configured_versions):
        return False
    if any(
        state.reserved_encryption_slots != state.nonce_count
        or not 0 <= state.reserved_encryption_slots <= 2**24
        for state in key_versions
    ):
        return False
    if not configured_versions:
        return not unexpired_versions and active_version is None
    if active_version not in configured_versions:
        return False
    states = {state.version: state for state in key_versions}
    if key_versions and active_version not in states:
        return False
    if any(
        version in states and states[version].retired
        for version in unexpired_versions
    ):
        return False
    active = states.get(active_version)
    return active is None or (
        not active.retired and (allow_active_write_disabled or not active.write_disabled)
    )


def load_idempotency_keyring(
    env: Mapping[str, str],
) -> IdempotencyKeyring | None:
    has_keyring = KEYRING_ENV in env
    has_active = ACTIVE_VERSION_ENV in env
    if not has_keyring and not has_active:
        return None
    if not has_keyring or not has_active:
        raise IdempotencyKeyringConfigError

    pairs = _parse_keyring_json(env[KEYRING_ENV])
    active_version = _parse_version_label(env[ACTIVE_VERSION_ENV])
    versions = tuple(
        sorted(
            (_parse_key_version(label, encoded) for label, encoded in pairs),
            key=lambda key: key.version,
        )
    )
    if not versions:
        raise IdempotencyKeyringConfigError
    if len({key.material for key in versions}) != len(versions):
        raise IdempotencyKeyringConfigError
    active_key = next(
        (key for key in versions if key.version == active_version),
        None,
    )
    if active_key is None:
        raise IdempotencyKeyringConfigError
    return IdempotencyKeyring(
        _active_key=active_key,
        _decryption_keys=versions,
    )


def key_commitment(material: bytes) -> IdempotencyKeyCommitment:
    return IdempotencyKeyCommitment(hashlib.sha256(KEY_COMMITMENT_DOMAIN + material).digest())


def validate_startup_compatibility(
    *,
    keyring: IdempotencyKeyring | None,
    registry: tuple[IdempotencyKeyRegistration, ...],
    unexpired_result_versions: tuple[str, ...],
) -> bool:
    if keyring is None:
        if unexpired_result_versions:
            raise IdempotencyKeyringConfigError
        return True

    configured_versions = set(keyring.version_labels)
    if any(version not in configured_versions for version in unexpired_result_versions):
        raise IdempotencyKeyringConfigError
    for registration in registry:
        for version in keyring._decryption_keys:
            same_label = registration.version == version.version
            same_commitment = registration.commitment == version.commitment
            if same_label != same_commitment:
                raise IdempotencyKeyringConfigError
    return True


def _parse_keyring_json(raw: str) -> tuple[tuple[str, str], ...]:
    try:
        parsed: _JsonValue = json.loads(raw, object_pairs_hook=_parse_object_pairs)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise IdempotencyKeyringConfigError from None
    match parsed:
        case _JsonObject(pairs=pairs):
            return pairs
        case str() | int() | float() | None | list():
            raise IdempotencyKeyringConfigError
        case unreachable:
            assert_never(unreachable)


def _parse_object_pairs(
    pairs: list[tuple[str, _JsonValue]],
) -> _JsonObject:
    labels: set[str] = set()
    parsed: list[tuple[str, str]] = []
    for label, value in pairs:
        if label in labels:
            raise IdempotencyKeyringConfigError
        labels.add(label)
        match value:
            case str() as encoded:
                parsed.append((label, encoded))
            case int() | float() | None | list() | _JsonObject():
                raise IdempotencyKeyringConfigError
            case unreachable:
                assert_never(unreachable)
    return _JsonObject(tuple(parsed))


def _parse_key_version(label: str, encoded: str) -> IdempotencyKeyVersion:
    version = _parse_version_label(label)
    if not encoded.isascii() or any(character.isspace() for character in encoded):
        raise IdempotencyKeyringConfigError
    try:
        material = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        raise IdempotencyKeyringConfigError from None
    if len(material) != _AES_256_KEY_BYTES:
        raise IdempotencyKeyringConfigError
    return IdempotencyKeyVersion(
        version=version,
        material=material,
        commitment=key_commitment(material),
    )


def _parse_version_label(raw: str) -> IdempotencyKeyVersionLabel:
    if _VERSION_LABEL.fullmatch(raw) is None:
        raise IdempotencyKeyringConfigError
    return IdempotencyKeyVersionLabel(raw)
