from __future__ import annotations

import errno
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from http.server import ThreadingHTTPServer
from typing import Any, NoReturn

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_http import create_v1_http_server
from vinctor_service.metrics import Metrics
from vinctor_service.oidc import PyJwtOidcTokenVerifier
from vinctor_service.postgres import PostgresV1Service, connect_postgres
from vinctor_service.postgres_control import PostgresLocalKeyRepository
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.sqlite import SQLiteV1Service


@dataclass
class ServiceRuntimeHandle:
    conn: Any
    service: SQLiteV1Service | PostgresV1Service
    key_repository: SQLiteLocalKeyRepository | PostgresLocalKeyRepository
    server: ThreadingHTTPServer
    config: ServiceRuntimeConfig
    endpoint: str

    def close(self) -> None:
        self.server.server_close()
        audit_writer = getattr(self.service, "audit_writer", None)
        close_export = getattr(audit_writer, "close_export", None)
        if callable(close_export):
            close_export()
        self.conn.close()


def prepare_service_runtime(
    config: ServiceRuntimeConfig,
    *,
    clock: Callable[[], datetime] | None = None,
) -> ServiceRuntimeHandle:
    if config.storage_backend == "postgres":
        assert config.postgres_dsn is not None
        conn = connect_postgres(config.postgres_dsn)
    else:
        db_path = config.sqlite_db_path.expanduser()
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        if config.storage_backend == "postgres":
            service = PostgresV1Service(conn)
            key_repository = PostgresLocalKeyRepository(conn)
            readiness_check = partial(_postgres_ready, conn)
        else:
            service = SQLiteV1Service(conn)
            key_repository = SQLiteLocalKeyRepository(conn)
            readiness_check = partial(_sqlite_ready, conn)
        metrics = Metrics() if config.metrics else None
        oidc_token_verifier = (
            PyJwtOidcTokenVerifier(config.oidc) if config.oidc is not None else None
        )
        server = create_v1_http_server(
            (config.host, config.port),
            service=service,
            agent_identities={},
            workspace_identities={},
            agent_identity_resolver=lambda raw_key, used_at: key_repository.resolve_agent_identity(
                raw_key,
                now=used_at,
            ),
            workspace_identity_resolver=lambda raw_key, used_at: (
                key_repository.resolve_workspace_identity(raw_key, now=used_at)
            ),
            auditor_identity_resolver=lambda raw_key, used_at: (
                key_repository.resolve_auditor_identity(raw_key, now=used_at)
            ),
            service_operator_resolver=lambda raw_key, used_at: (
                key_repository.resolve_service_operator(raw_key, now=used_at)
            ),
            pep_identity_resolver=lambda raw_key, used_at: key_repository.resolve_pep_identity(
                raw_key, now=used_at
            ),
            clock=clock,
            service_mode=config.service_mode,
            metrics=metrics,
            access_log=config.access_log,
            readiness_check=readiness_check,
            oidc_token_verifier=oidc_token_verifier,
        )
    except Exception:
        conn.close()
        raise

    host, port = server.server_address
    return ServiceRuntimeHandle(
        conn=conn,
        service=service,
        key_repository=key_repository,
        server=server,
        config=config,
        endpoint=f"http://{host}:{port}",
    )


def _sqlite_ready(conn: sqlite3.Connection) -> bool:
    return conn.execute("SELECT 1").fetchone() == (1,)


def _postgres_ready(conn: Any) -> bool:
    with conn.transaction():
        return conn.execute("SELECT 1").fetchone() == (1,)


def render_service_runtime_banner(handle: ServiceRuntimeHandle) -> str:
    return "\n".join(
        [
            "# Vinctor service listening",
            f"# URL: {handle.endpoint}",
            f"# mode: {handle.config.service_mode}",
            f"# database: {_database_label(handle.config)}",
            f"# log_level: {handle.config.log_level}",
            "# Local/self-hostable prototype only; not a hosted production service.",
            "# This command does not print raw keys. Bootstrap keys separately when needed.",
            "# Press Ctrl+C to stop.",
        ]
    )


def _database_label(config: ServiceRuntimeConfig) -> str:
    if config.storage_backend == "postgres":
        return "postgres"
    return str(config.sqlite_db_path)


def serve_service_runtime(config: ServiceRuntimeConfig) -> NoReturn:
    try:
        handle = prepare_service_runtime(config)
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            from vinctor_service.cli import EXIT_SERVICE, CliError

            raise CliError(
                f"port {config.port} already in use — pass --port <n> "
                "(or --port 0 for any free port)",
                code=EXIT_SERVICE,
            ) from error
        raise
    print(render_service_runtime_banner(handle), flush=True)
    try:
        handle.server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()
    raise SystemExit(0)
