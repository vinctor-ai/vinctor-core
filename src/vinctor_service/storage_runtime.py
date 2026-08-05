from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import Any

from vinctor_service.idempotency_readiness import (
    postgres_idempotency_ready,
    require_postgres_idempotency_compatible,
    require_postgres_idempotency_ready,
    sqlite_idempotency_ready,
)
from vinctor_service.postgres import PostgresV1Service, connect_postgres
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite


@dataclass
class DecisionStorageHandle:
    """A ready grant/audit decision-store connection and service."""

    backend: str
    conn: Any
    service: SQLiteV1Service | PostgresV1Service

    def is_ready(self) -> bool:
        try:
            if self.backend == "postgres":
                if getattr(self.conn, "is_ready", True) is False:
                    return False
                with self.conn.transaction():
                    row = self.conn.execute("SELECT 1").fetchone()
                    compatible = postgres_idempotency_ready(
                        self.conn,
                        self.service.idempotency_keyring,
                    )
            else:
                row = self.conn.execute("SELECT 1").fetchone()
                compatible = sqlite_idempotency_ready(
                    self.conn,
                    self.service.idempotency_keyring,
                )
        except Exception:
            return False
        return row == (1,) and compatible

    def close(self) -> None:
        self.service.close()
        self.conn.close()


def prepare_decision_storage(config: ServiceRuntimeConfig) -> DecisionStorageHandle:
    """Select, initialize, and verify the currently supported decision store."""
    if config.storage_backend == "postgres":
        assert config.postgres_dsn is not None
        conn = connect_postgres(config.postgres_dsn)
        backend = "postgres"
        service_factory = (
            PostgresV1Service
            if config.idempotency_keyring is None
            else partial(
                PostgresV1Service,
                idempotency_keyring=config.idempotency_keyring,
            )
        )
    else:
        db_path = config.sqlite_db_path.expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect_sqlite(str(db_path), check_same_thread=False)
        backend = "sqlite"
        service_factory = (
            SQLiteV1Service
            if config.idempotency_keyring is None
            else partial(
                SQLiteV1Service,
                idempotency_keyring=config.idempotency_keyring,
            )
        )

    service: SQLiteV1Service | PostgresV1Service | None = None
    try:
        service = service_factory(conn)
        if backend == "postgres":
            add_replacement_validator = getattr(conn, "add_replacement_validator", None)
            if callable(add_replacement_validator):
                add_replacement_validator(
                    partial(
                        require_postgres_idempotency_compatible,
                        keyring=config.idempotency_keyring,
                    )
                )
            add_readiness_validator = getattr(conn, "add_readiness_validator", None)
            if callable(add_readiness_validator):
                add_readiness_validator(
                    partial(
                        require_postgres_idempotency_ready,
                        keyring=config.idempotency_keyring,
                    )
                )
        handle = DecisionStorageHandle(backend=backend, conn=conn, service=service)
        if not handle.is_ready():
            raise RuntimeError(f"{backend} storage readiness check failed")
    except Exception:
        if service is not None:
            service.close()
        conn.close()
        raise
    assert service is not None
    return handle
