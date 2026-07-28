from __future__ import annotations

from pathlib import Path

import pytest
from idempotency_runtime_fixtures import (
    configured_env as _configured_env,
)

from vinctor_service.sqlite import init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


def test_schema_maintenance_window_blocks_mixed_binary_rollout(tmp_path: Path) -> None:
    from vinctor_service.idempotency_lifecycle import IdempotencyLifecycleController

    database = tmp_path / "maintenance.sqlite3"
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_configured_env(database),
    )
    controller.register_active_writer("old-binary")
    with pytest.raises(RuntimeError):
        controller.migrate_schema(confirm_traffic_closed=True)

def test_schema_rollback_restores_verified_pre_window_snapshot_not_version_rows(
    tmp_path: Path,
) -> None:
    from vinctor_service.idempotency_lifecycle import IdempotencyLifecycleController

    database = tmp_path / "rollback.sqlite3"
    snapshot = tmp_path / "before.sqlite3"
    connection = connect_sqlite(database)
    init_sqlite_schema(connection)
    connection.close()
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_configured_env(database),
    )
    controller.create_verified_snapshot(snapshot)
    controller.migrate_schema(confirm_traffic_closed=True)
    controller.restore_verified_snapshot(snapshot)
    assert controller.schema_versions() == tuple(range(1, 19))
