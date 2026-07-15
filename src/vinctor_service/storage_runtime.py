from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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
                with self.conn.transaction():
                    row = self.conn.execute("SELECT 1").fetchone()
            else:
                row = self.conn.execute("SELECT 1").fetchone()
        except Exception:
            return False
        return row == (1,)

    def close(self) -> None:
        self.conn.close()


def prepare_decision_storage(config: ServiceRuntimeConfig) -> DecisionStorageHandle:
    """Select, initialize, and verify the currently supported decision store."""
    if config.storage_backend == "postgres":
        assert config.postgres_dsn is not None
        conn = connect_postgres(config.postgres_dsn)
        backend = "postgres"
        service_factory = PostgresV1Service
    else:
        db_path = config.sqlite_db_path.expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect_sqlite(str(db_path), check_same_thread=False)
        backend = "sqlite"
        service_factory = SQLiteV1Service

    try:
        service = service_factory(conn)
        handle = DecisionStorageHandle(backend=backend, conn=conn, service=service)
        if not handle.is_ready():
            raise RuntimeError(f"{backend} storage readiness check failed")
    except Exception:
        conn.close()
        raise
    return handle
