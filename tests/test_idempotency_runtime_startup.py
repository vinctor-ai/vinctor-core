from __future__ import annotations

from pathlib import Path

import pytest
from idempotency_runtime_fixtures import (
    ACTIVE_ENV,
    KEYS_ENV,
    READINESS_CASES,
    ReadinessCase,
    configured_secret_values,
)
from idempotency_runtime_fixtures import (
    configured_env as _configured_env,
)
from idempotency_runtime_startup_scenarios import (
    exercise_commitment_mismatch_startup,
    exercise_unknown_unexpired_version_startup,
)

from vinctor_service.service_config import load_service_runtime_config


def test_startup_allows_fully_absent_config_only_without_unexpired_results(
    tmp_path: Path,
) -> None:
    from vinctor_service.idempotency_keyring import validate_startup_compatibility

    assert validate_startup_compatibility(
        keyring=None,
        registry=(),
        unexpired_result_versions=(),
    )
    with pytest.raises(ValueError):
        validate_startup_compatibility(
            keyring=None,
            registry=(),
            unexpired_result_versions=("primary",),
        )

def test_startup_rejects_partial_malformed_unknown_and_commitment_mismatch_config(
    tmp_path: Path,
) -> None:
    env = _configured_env(tmp_path / "startup.sqlite3")
    invalid = (
        {KEYS_ENV: env[KEYS_ENV]},
        {ACTIVE_ENV: "primary"},
        {KEYS_ENV: "not-json", ACTIVE_ENV: "primary"},
    )
    configuration_errors: list[str] = []
    for values in invalid:
        with pytest.raises(ValueError) as captured:
            load_service_runtime_config(env=values)
        configuration_errors.append(str(captured.value))
    unknown = exercise_unknown_unexpired_version_startup(
        tmp_path / "unknown.sqlite3",
        {**env, "VINCTOR_DB": str(tmp_path / "unknown.sqlite3")},
    )
    mismatch = exercise_commitment_mismatch_startup(
        tmp_path / "mismatch.sqlite3",
        {**env, "VINCTOR_DB": str(tmp_path / "mismatch.sqlite3")},
    )
    assert (unknown.error_type, mismatch.error_type) == (
        "IdempotencyKeyringConfigError",
        "IdempotencyKeyringConfigError",
    )
    assert unknown.error_text == mismatch.error_text
    assert unknown.registry_rows >= 1
    assert unknown.result_rows == 1
    assert (mismatch.registry_rows, mismatch.result_rows) == (1, 0)
    rendered_errors = "\n".join((*configuration_errors, unknown.error_text, mismatch.error_text))
    assert all(secret not in rendered_errors for secret in configured_secret_values(env))

def test_readiness_turns_false_when_an_unknown_unexpired_version_appears(
    tmp_path: Path,
) -> None:
    from vinctor_service.idempotency_keyring import idempotency_readiness

    assert (
        idempotency_readiness(
            configured_versions={"primary"},
            unexpired_versions={"unknown"},
            active_version="primary",
        )
        is False
    )

def test_readiness_rejects_any_result_left_under_a_retired_version() -> None:
    # Given a corrupt or otherwise impossible leftover row under a retired version.
    from vinctor_service.idempotency_keyring import (
        KeyVersionReadinessState,
        idempotency_readiness,
    )

    # When readiness evaluates the versions referenced by every remaining result.
    ready = idempotency_readiness(
        configured_versions={"old", "primary"},
        unexpired_versions={"old"},
        active_version="primary",
        key_versions=(
            KeyVersionReadinessState("old", True, True, 1, 1),
            KeyVersionReadinessState("primary", False, False, 0, 0),
        ),
    )

    # Then an impossible post-retirement leftover fails readiness closed.
    assert ready is False

@pytest.mark.parametrize("case", READINESS_CASES, ids=lambda case: case.name)
def test_readiness_rejects_active_disabled_retired_count_mismatch_and_limit_overflow(
    case: ReadinessCase,
) -> None:
    # Given a persisted active-key state with one incompatible readiness condition.
    from vinctor_service.idempotency_keyring import (
        KeyVersionReadinessState,
        idempotency_readiness,
    )

    state = KeyVersionReadinessState(
        version="primary",
        write_disabled=case.active_disabled,
        retired=case.active_retired,
        reserved_encryption_slots=case.reserved_slots,
        nonce_count=case.nonce_count,
    )
    # When the public readiness evaluator checks the actual persisted counts/barriers.
    ready = idempotency_readiness(
        configured_versions={"primary"},
        unexpired_versions=set(),
        active_version="primary",
        key_versions=(state,),
    )
    # Then each incompatible state fails closed.
    assert ready is False
