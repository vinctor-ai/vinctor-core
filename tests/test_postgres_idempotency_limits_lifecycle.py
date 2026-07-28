from __future__ import annotations

import pytest

from vinctor_service.postgres import (
    connect_postgres,
)


def test_postgres_lifecycle_uses_db_time_and_preserves_retired_tombstone(
    requires_postgres: str,
) -> None:
    import base64

    from vinctor_service.idempotency_lifecycle import (
        IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
        IdempotencyLifecycleController,
        IdempotencyLifecycleRejected,
        IdempotencyRetirementRequest,
    )
    from vinctor_service.service_config import load_service_runtime_config

    old_key = base64.b64encode(b"o" * 32).decode("ascii")
    active_key = base64.b64encode(b"a" * 32).decode("ascii")
    config = load_service_runtime_config(
        env={
            "VINCTOR_STORAGE_BACKEND": "postgres",
            "VINCTOR_POSTGRES_DSN": requires_postgres,
            "VINCTOR_IDEMPOTENCY_KEYRING_JSON": (f'{{"active":"{active_key}","old":"{old_key}"}}'),
            "VINCTOR_IDEMPOTENCY_ACTIVE_KEY_VERSION": "active",
        }
    )
    with IdempotencyLifecycleController.from_config(config) as controller:
        with pytest.raises(IdempotencyLifecycleRejected, match="active_version_rejected"):
            controller.write_disable(version="active", reason="rotation")
        controller.write_disable(version="old", reason="rotation")
        controller.complete_drain(
            version="old",
            confirm_no_active_writers=True,
        )
        request = IdempotencyRetirementRequest(
            version="old",
            confirm_removal_window=True,
        )
        with pytest.raises(
            IdempotencyLifecycleRejected,
            match="removal_window_not_elapsed",
        ):
            controller.retire(request)
        maintenance = connect_postgres(requires_postgres)
        try:
            with maintenance.transaction():
                maintenance.execute(
                    "UPDATE idempotency_cipher_key_versions "
                    "SET first_seen_epoch = "
                    "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s - 2, "
                    "write_disabled_epoch = "
                    "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s - 1, "
                    "drain_completed_epoch = "
                    "FLOOR(EXTRACT(EPOCH FROM clock_timestamp()))::BIGINT - %s "
                    "WHERE version_label = %s",
                    (
                        IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                        IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                        IDEMPOTENCY_REMOVAL_WINDOW_SECONDS,
                        "old",
                    ),
                )
        finally:
            maintenance.close()
        controller.retire(request)
        controller.retire(request)
        retired = controller.status("old")
        assert retired.retired_epoch is not None
        assert retired.reserved_encryption_slots == 0

    with IdempotencyLifecycleController.from_config(config) as restarted:
        assert restarted.status("old").retired_epoch == retired.retired_epoch
