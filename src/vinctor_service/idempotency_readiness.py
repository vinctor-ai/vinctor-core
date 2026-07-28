from __future__ import annotations

from typing import Any

from vinctor_service.idempotency_keyring import (
    IdempotencyKeyring,
    KeyVersionReadinessState,
    idempotency_readiness,
    validate_startup_compatibility,
)
from vinctor_service.idempotency_models import (
    IdempotencyKeyCommitment,
    IdempotencyKeyRegistration,
    IdempotencyKeyVersionLabel,
)


def postgres_idempotency_ready(
    conn: Any,
    keyring: IdempotencyKeyring | None,
    *,
    exact_nonce_counts: bool = False,
    allow_active_write_disabled: bool = False,
) -> bool:
    registry_rows = conn.execute(
        "SELECT version_label, key_commitment, reserved_encryption_slots, "
        "write_disabled_epoch, retired_epoch "
        "FROM idempotency_cipher_key_versions ORDER BY version_label"
    ).fetchall()
    result_version_rows = conn.execute(
        "SELECT DISTINCT cipher_key_version FROM idempotency_results "
        "ORDER BY cipher_key_version"
    ).fetchall()
    nonce_counts = (
        {
            str(row[0]): int(row[1])
            for row in conn.execute(
                "SELECT cipher_key_version, COUNT(*) "
                "FROM idempotency_cipher_nonces GROUP BY cipher_key_version"
            ).fetchall()
        }
        if exact_nonce_counts
        else {str(row[0]): int(row[2]) for row in registry_rows}
    )
    return _evaluate(
        registry_rows,
        result_version_rows,
        nonce_counts,
        keyring,
        allow_active_write_disabled=allow_active_write_disabled,
    )


def sqlite_idempotency_ready(
    conn: Any,
    keyring: IdempotencyKeyring | None,
    *,
    exact_nonce_counts: bool = False,
) -> bool:
    registry_rows = conn.execute(
        "SELECT version_label, key_commitment, reserved_encryption_slots, "
        "write_disabled_epoch, retired_epoch "
        "FROM idempotency_cipher_key_versions ORDER BY version_label"
    ).fetchall()
    result_version_rows = conn.execute(
        "SELECT DISTINCT cipher_key_version FROM idempotency_results "
        "ORDER BY cipher_key_version"
    ).fetchall()
    nonce_counts = (
        {
            str(row[0]): int(row[1])
            for row in conn.execute(
                "SELECT cipher_key_version, COUNT(*) "
                "FROM idempotency_cipher_nonces GROUP BY cipher_key_version"
            ).fetchall()
        }
        if exact_nonce_counts
        else {str(row[0]): int(row[2]) for row in registry_rows}
    )
    return _evaluate(registry_rows, result_version_rows, nonce_counts, keyring)


def require_postgres_idempotency_ready(
    conn: Any,
    *,
    keyring: IdempotencyKeyring | None,
) -> None:
    if not postgres_idempotency_ready(conn, keyring):
        raise RuntimeError("PostgreSQL idempotency readiness check failed")


def require_postgres_idempotency_compatible(
    conn: Any,
    *,
    keyring: IdempotencyKeyring | None,
) -> None:
    if not postgres_idempotency_ready(
        conn,
        keyring,
        allow_active_write_disabled=True,
    ):
        raise RuntimeError("PostgreSQL idempotency compatibility check failed")


def _evaluate(
    registry_rows: list[Any],
    result_version_rows: list[Any],
    nonce_counts: dict[str, int],
    keyring: IdempotencyKeyring | None,
    *,
    allow_active_write_disabled: bool = False,
) -> bool:
    registry = tuple(
        IdempotencyKeyRegistration(
            version=IdempotencyKeyVersionLabel(str(row[0])),
            commitment=IdempotencyKeyCommitment(bytes(row[1])),
        )
        for row in registry_rows
    )
    required_versions = tuple(str(row[0]) for row in result_version_rows)
    validate_startup_compatibility(
        keyring=keyring,
        registry=registry,
        unexpired_result_versions=required_versions,
    )
    states = tuple(
        KeyVersionReadinessState(
            version=str(row[0]),
            write_disabled=row[3] is not None,
            retired=row[4] is not None,
            reserved_encryption_slots=int(row[2]),
            nonce_count=nonce_counts.get(str(row[0]), 0),
        )
        for row in registry_rows
    )
    return idempotency_readiness(
        configured_versions=set() if keyring is None else set(keyring.version_labels),
        unexpired_versions=set(required_versions),
        active_version=None if keyring is None else keyring.active_version,
        key_versions=states,
        allow_active_write_disabled=allow_active_write_disabled,
    )
