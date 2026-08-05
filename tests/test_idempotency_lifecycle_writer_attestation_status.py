from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
from dataclasses import fields
from pathlib import Path

import pytest
from idempotency_lifecycle_writer_attestation_fixtures import (
    _PRIMARY,
    _RETIRING,
    _age_drain,
    _hold_primary_service,
    _keyring,
    _lifecycle_env,
)

from vinctor_service.idempotency_lifecycle import (
    IdempotencyLifecycleActiveWriters,
    IdempotencyLifecycleController,
    IdempotencyLifecycleStatus,
    IdempotencyRetirementRequest,
)
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite


def test_public_status_and_installed_json_omit_unexpired_result_count(
    tmp_path: Path,
) -> None:
    public_fields = {field.name for field in fields(IdempotencyLifecycleStatus)}
    assert "unexpired_result_count" not in public_fields

    database = tmp_path / "status.sqlite3"
    executable = Path(sys.executable).with_name("vinctor")
    completed = subprocess.run(
        (
            str(executable),
            "--json",
            "--db",
            str(database),
            "operator",
            "idempotency",
            "status",
        ),
        cwd=Path(__file__).parents[1],
        env=os.environ | _lifecycle_env(database) | {"PYTHONPATH": "src"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert all("unexpired_result_count" not in version for version in payload["versions"])

def test_old_service_blocks_target_drain_and_retire_until_exact_release(
    tmp_path: Path,
) -> None:
    database = tmp_path / "old-writer.sqlite3"
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=_keyring(_RETIRING))
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    )
    try:
        controller.write_disable(version=_RETIRING, reason="rotation")
        with pytest.raises(IdempotencyLifecycleActiveWriters):
            controller.complete_drain(
                version=_RETIRING,
                confirm_no_active_writers=True,
            )
        _age_drain(database)
        with pytest.raises(IdempotencyLifecycleActiveWriters):
            controller.retire(
                IdempotencyRetirementRequest(
                    version=_RETIRING,
                    confirm_removal_window=True,
                )
            )
    finally:
        service.close()
        service.close()
        connection.close()
        controller.close()

    with IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    ) as restarted:
        restarted.retire(
            IdempotencyRetirementRequest(
                version=_RETIRING,
                confirm_removal_window=True,
            )
        )
        assert restarted.status(_RETIRING).retired_epoch is not None

def test_primary_only_service_allows_target_drain_and_retire(
    tmp_path: Path,
) -> None:
    database = tmp_path / "primary-writer.sqlite3"
    connection = connect_sqlite(database, check_same_thread=False)
    service = SQLiteV1Service(connection, idempotency_keyring=_keyring(_PRIMARY))
    controller = IdempotencyLifecycleController.sqlite(
        database,
        env=_lifecycle_env(database),
    )
    try:
        controller.write_disable(version=_RETIRING, reason="rotation")
        controller.complete_drain(
            version=_RETIRING,
            confirm_no_active_writers=True,
        )
        _age_drain(database)
        controller.retire(
            IdempotencyRetirementRequest(
                version=_RETIRING,
                confirm_removal_window=True,
            )
        )
        assert controller.status(_RETIRING).retired_epoch is not None
    finally:
        service.close()
        connection.close()
        controller.close()

def test_cross_process_primary_carrier_is_target_separated_and_redacted(
    tmp_path: Path,
) -> None:
    database = tmp_path / "process.sqlite3"
    context = multiprocessing.get_context("spawn")
    ready_reader, ready_writer = context.Pipe(duplex=False)
    release_reader, release_writer = context.Pipe(duplex=False)
    process = context.Process(
        target=_hold_primary_service,
        args=(str(database), ready_writer, release_reader),
    )
    process.start()
    ready_writer.close()
    release_reader.close()
    try:
        assert ready_reader.poll(5)
        assert ready_reader.recv_bytes() == b"1"
        with IdempotencyLifecycleController.sqlite(
            database,
            env=_lifecycle_env(database),
        ) as controller:
            controller.write_disable(version=_RETIRING, reason="rotation")
            controller.complete_drain(
                version=_RETIRING,
                confirm_no_active_writers=True,
            )
        lock_names = tuple(path.name for path in tmp_path.glob("*.lock"))
        assert lock_names
        assert all(_RETIRING not in name and _PRIMARY not in name for name in lock_names)
    finally:
        release_writer.send_bytes(b"1")
        release_writer.close()
        ready_reader.close()
        process.join(timeout=5)
        if process.is_alive():
            process.terminate()
            process.join(timeout=5)
    assert process.exitcode == 0
