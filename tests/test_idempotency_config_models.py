from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import os
import tomllib
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_launcher import _parse_args
from vinctor_service.service_config import load_service_runtime_config
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_pool import SQLiteServicePool
from vinctor_service.sqlite_txn import connect_sqlite
from vinctor_service.storage_runtime import prepare_decision_storage

KEYRING_ENV = "VINCTOR_IDEMPOTENCY_KEYRING_JSON"
ACTIVE_ENV = "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION"
COMMITMENT_DOMAIN = b"vinctor.idempotency.key-commitment.v1\x00"


def _two_version_env() -> dict[str, str]:
    old = base64.b64encode(b"o" * 32).decode("ascii")
    primary = base64.b64encode(b"p" * 32).decode("ascii")
    return {
        KEYRING_ENV: f'{{"old":"{old}","primary":"{primary}"}}',
        ACTIVE_ENV: "primary",
    }


def test_cryptography_49_is_a_direct_runtime_dependency() -> None:
    # Given the installed environment and project dependency metadata.
    metadata = tomllib.loads(Path("pyproject.toml").read_text())

    # When the resolved package and direct dependencies are inspected.
    resolved = importlib.metadata.version("cryptography")
    dependencies = metadata["project"]["dependencies"]

    # Then the declared and installed versions are the approved 49.x line.
    assert "cryptography>=49,<50" in dependencies
    assert resolved.split(".", maxsplit=1)[0] == "49"


def test_two_version_keyring_has_one_active_key_and_historical_decryption() -> None:
    # Given one active key and one historical decrypt-only key.
    from vinctor_service.idempotency_keyring import load_idempotency_keyring

    env = _two_version_env()

    # When the strict boundary parses the complete pair.
    keyring = load_idempotency_keyring(env)

    # Then only the selected primary is exposed for encryption and both decrypt.
    assert keyring is not None
    assert keyring.active_version == "primary"
    assert keyring.active_key.version == "primary"
    assert keyring.active_key.material == b"p" * 32
    assert keyring.decryption_key("old").material == b"o" * 32
    assert keyring.decryption_key("primary") == keyring.active_key
    assert keyring.decryption_key("missing") is None
    assert keyring.active_key.commitment == hashlib.sha256(COMMITMENT_DOMAIN + (b"p" * 32)).digest()


def test_startup_compatibility_allows_drained_tombstones_and_rejects_unsafe_matrix() -> None:
    # Given a configured keyring and permanent matching and historical tombstones.
    from vinctor_service.idempotency_keyring import (
        IdempotencyKeyringConfigError,
        key_commitment,
        load_idempotency_keyring,
        validate_startup_compatibility,
    )
    from vinctor_service.idempotency_models import (
        IdempotencyKeyCommitment,
        IdempotencyKeyRegistration,
        IdempotencyKeyVersionLabel,
    )

    keyring = load_idempotency_keyring(_two_version_env())
    assert keyring is not None
    matching = IdempotencyKeyRegistration(
        version=IdempotencyKeyVersionLabel("old"),
        commitment=key_commitment(b"o" * 32),
    )
    historical = IdempotencyKeyRegistration(
        version=IdempotencyKeyVersionLabel("retired"),
        commitment=IdempotencyKeyCommitment(b"h" * 32),
    )
    mismatched_label = IdempotencyKeyRegistration(
        version=IdempotencyKeyVersionLabel("old"),
        commitment=IdempotencyKeyCommitment(b"m" * 32),
    )
    reused_commitment = IdempotencyKeyRegistration(
        version=IdempotencyKeyVersionLabel("renamed"),
        commitment=key_commitment(b"o" * 32),
    )

    # When startup checks drained tombstones and every fail-closed incompatibility.
    assert validate_startup_compatibility(
        keyring=None,
        registry=(matching, historical),
        unexpired_result_versions=(),
    )
    assert validate_startup_compatibility(
        keyring=keyring,
        registry=(matching, historical),
        unexpired_result_versions=(),
    )
    unsafe = (
        (None, (matching,), ("old",)),
        (keyring, (matching,), ("unknown",)),
        (keyring, (mismatched_label,), ()),
        (keyring, (reused_commitment,), ()),
    )

    # Then only unexpired unavailable keys or label/commitment conflicts are rejected.
    for candidate, registry, unexpired_versions in unsafe:
        with pytest.raises(IdempotencyKeyringConfigError):
            validate_startup_compatibility(
                keyring=candidate,
                registry=registry,
                unexpired_result_versions=unexpired_versions,
            )


def test_keyring_and_runtime_config_are_immutable_and_secret_redacting() -> None:
    # Given a valid secret-bearing keyring and PostgreSQL DSN.
    from vinctor_service.idempotency_keyring import (
        IdempotencyKeyringConfigError,
    )

    env = {
        **_two_version_env(),
        "VINCTOR_STORAGE_BACKEND": "postgres",
        "VINCTOR_POSTGRES_DSN": "postgresql://operator:dsn-secret@db.example/vinctor",
    }

    # When runtime configuration parses it and malformed input is rejected.
    config = load_service_runtime_config(env=env)
    keyring = config.idempotency_keyring
    assert keyring is not None
    with pytest.raises((FrozenInstanceError, TypeError)):
        keyring.__setattr__("active_version", "old")
    with pytest.raises(IdempotencyKeyringConfigError) as captured:
        load_service_runtime_config(env={KEYRING_ENV: env[KEYRING_ENV], ACTIVE_ENV: "missing"})

    # Then repr and error surfaces expose none of the configured secret values.
    rendered = "\n".join((repr(config), repr(keyring), repr(captured.value), str(captured.value)))
    secrets = (
        env[KEYRING_ENV],
        base64.b64encode(b"o" * 32).decode("ascii"),
        base64.b64encode(b"p" * 32).decode("ascii"),
        env["VINCTOR_POSTGRES_DSN"],
    )
    assert all(secret not in rendered for secret in secrets)
    assert str(captured.value) == "invalid idempotency key configuration"


def test_local_runtime_construction_parses_the_same_operator_keyring(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    # Given the local launcher process receives the exact operator environment pair.
    env = _two_version_env()
    monkeypatch.setenv(KEYRING_ENV, env[KEYRING_ENV])
    monkeypatch.setenv(ACTIVE_ENV, env[ACTIVE_ENV])

    # When its production argument boundary constructs the local runtime config.
    config = _parse_args(["--db", os.fspath(tmp_path / "local.sqlite"), "--port", "0"])

    # Then it carries the same immutable typed keyring before any server bind.
    assert config.idempotency_keyring is not None
    assert config.idempotency_keyring.active_version == "primary"


def test_storage_runtime_injects_the_typed_keyring_into_the_service(
    tmp_path: Path,
) -> None:
    # Given a validated service config with a complete keyring.
    config = load_service_runtime_config(
        env={
            **_two_version_env(),
            "VINCTOR_DB": os.fspath(tmp_path / "storage.sqlite"),
        }
    )

    # When the production storage runtime constructs its backend service.
    handle = prepare_decision_storage(config)

    # Then the service receives the exact immutable instance parsed at the boundary.
    try:
        assert handle.service.idempotency_keyring is config.idempotency_keyring
    finally:
        handle.close()


def test_sqlite_pool_shares_one_typed_keyring_across_connection_services(
    tmp_path: Path,
) -> None:
    # Given a primary SQLite service with one validated process keyring.
    config = load_service_runtime_config(env=_two_version_env())
    connection = connect_sqlite(tmp_path / "pool.sqlite", check_same_thread=False)
    service = SQLiteV1Service(
        connection,
        idempotency_keyring=config.idempotency_keyring,
    )
    pool = SQLiteServicePool(
        tmp_path / "pool.sqlite",
        primary_connection=connection,
        primary_service=service,
        primary_key_repository=SQLiteLocalKeyRepository(connection),
        size=2,
    )

    # When the pool has constructed every connection-bound service.
    keyrings = tuple(context.service.idempotency_keyring for context in pool._contexts)

    # Then every lease shares one process-level immutable keyring instance.
    try:
        assert keyrings == (config.idempotency_keyring, config.idempotency_keyring)
    finally:
        pool.close()
