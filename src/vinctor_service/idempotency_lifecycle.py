from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Protocol

from vinctor_service.idempotency_models import IdempotencyInvocation
from vinctor_service.service_config import (
    ServiceRuntimeConfig,
    load_service_runtime_config,
)

_ROTATION_REASON = "rotation"
IDEMPOTENCY_REMOVAL_WINDOW_SECONDS = 86_400 + 300
_PROBE_INVOCATION = IdempotencyInvocation(
    workspace_id="lifecycle",
    principal="operator",
    operation="idempotency.lifecycle.probe.v1",
    key_hash=b"\x00" * 32,
    request_fingerprint=b"\x01" * 32,
    max_terminal_ttl_seconds=86_400,
)


class IdempotencyLifecycleUnavailable(RuntimeError):
    def __str__(self) -> str:
        return "idempotency_unavailable"


@dataclass(slots=True)
class IdempotencyLifecycleRejected(ValueError):
    reason: str

    def __str__(self) -> str:
        return self.reason


class IdempotencyLifecycleActiveWriters(RuntimeError):
    def __str__(self) -> str:
        return "active_idempotency_writers"


@dataclass(frozen=True, slots=True)
class IdempotencyLifecycleStatus:
    version: str
    commitment_identifier: str
    reserved_encryption_slots: int
    write_disabled_reason: str | None
    write_disabled_epoch: int | None
    drain_completed_epoch: int | None
    retired_epoch: int | None
    local_active_version: str
    required_historical_versions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IdempotencyRetirementRequest:
    version: str
    confirm_removal_window: bool


class IdempotencyLifecycleBackend(Protocol):
    def statuses(self) -> tuple[IdempotencyLifecycleStatus, ...]: ...

    def status(self, version: str) -> IdempotencyLifecycleStatus: ...

    def write_disable(self, version: str, reason: str) -> None: ...

    def complete_drain(self, version: str) -> None: ...

    def retire(self, request: IdempotencyRetirementRequest) -> None: ...

    def reserve_nonce(self, version: str) -> None: ...

    def register_active_writer(self, writer_id: str) -> None: ...

    def migrate_schema(self, *, confirm_traffic_closed: bool) -> None: ...

    def create_verified_snapshot(self, snapshot: Path) -> None: ...

    def restore_verified_snapshot(self, snapshot: Path) -> None: ...

    def schema_versions(self) -> tuple[int, ...]: ...

    def close(self) -> None: ...


class IdempotencyLifecycleController:
    __slots__ = ("_active_version", "_backend")

    def __init__(
        self,
        backend: IdempotencyLifecycleBackend,
        *,
        active_version: str,
    ) -> None:
        self._backend = backend
        self._active_version = active_version

    @classmethod
    def sqlite(
        cls,
        database: Path,
        *,
        env: Mapping[str, str],
    ) -> IdempotencyLifecycleController:
        config = load_service_runtime_config(
            sqlite_db_path=database,
            storage_backend="sqlite",
            env=env,
        )
        return cls._from_config(config)

    @classmethod
    def from_config(
        cls,
        config: ServiceRuntimeConfig,
    ) -> IdempotencyLifecycleController:
        return cls._from_config(config)

    @classmethod
    def _from_config(
        cls,
        config: ServiceRuntimeConfig,
    ) -> IdempotencyLifecycleController:
        keyring = config.idempotency_keyring
        if keyring is None:
            raise IdempotencyLifecycleUnavailable
        try:
            if config.storage_backend == "sqlite":
                from vinctor_service.idempotency_lifecycle_sqlite import (
                    SQLiteIdempotencyLifecycleBackend,
                )

                backend: IdempotencyLifecycleBackend = SQLiteIdempotencyLifecycleBackend(
                    config.sqlite_db_path,
                    keyring=keyring,
                )
            else:
                from vinctor_service.idempotency_lifecycle_postgres import (
                    PostgresIdempotencyLifecycleBackend,
                )

                if config.postgres_dsn is None:
                    raise IdempotencyLifecycleUnavailable
                backend = PostgresIdempotencyLifecycleBackend(
                    config.postgres_dsn,
                    keyring=keyring,
                )
        except IdempotencyLifecycleUnavailable:
            raise
        except (OSError, RuntimeError):
            raise IdempotencyLifecycleUnavailable from None
        return cls(backend, active_version=keyring.active_version)

    def statuses(self) -> tuple[IdempotencyLifecycleStatus, ...]:
        return self._backend.statuses()

    def status(self, version: str) -> IdempotencyLifecycleStatus:
        return self._backend.status(version)

    def write_disable(self, *, version: str, reason: str) -> None:
        self._require_old_version(version)
        if reason != _ROTATION_REASON:
            raise IdempotencyLifecycleRejected("rotation_reason_required")
        self._backend.write_disable(version, reason)

    def complete_drain(
        self,
        *,
        version: str,
        confirm_no_active_writers: bool,
    ) -> None:
        self._require_old_version(version)
        if not confirm_no_active_writers:
            raise IdempotencyLifecycleRejected("active_writer_confirmation_required")
        self._backend.complete_drain(version)

    def retire(self, request: IdempotencyRetirementRequest) -> None:
        self._require_old_version(request.version)
        if not request.confirm_removal_window:
            raise IdempotencyLifecycleRejected("removal_window_confirmation_required")
        self._backend.retire(request)

    def reserve_nonce(self, *, version: str) -> None:
        self._backend.reserve_nonce(version)

    def register_active_writer(self, writer_id: str) -> None:
        self._backend.register_active_writer(writer_id)

    def migrate_schema(self, *, confirm_traffic_closed: bool) -> None:
        self._backend.migrate_schema(confirm_traffic_closed=confirm_traffic_closed)

    def create_verified_snapshot(self, snapshot: Path) -> None:
        self._backend.create_verified_snapshot(snapshot)

    def restore_verified_snapshot(self, snapshot: Path) -> None:
        self._backend.restore_verified_snapshot(snapshot)

    def schema_versions(self) -> tuple[int, ...]:
        return self._backend.schema_versions()

    def close(self) -> None:
        self._backend.close()

    def __enter__(self) -> IdempotencyLifecycleController:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _require_old_version(self, version: str) -> None:
        if not version:
            raise IdempotencyLifecycleRejected("version_required")
        if version == self._active_version:
            raise IdempotencyLifecycleRejected("active_version_rejected")
