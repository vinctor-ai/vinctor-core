from __future__ import annotations

import errno
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from http.server import ThreadingHTTPServer
from typing import NoReturn

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_http import create_v1_http_server
from vinctor_service.metrics import Metrics
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.sqlite import SQLiteV1Service


@dataclass
class ServiceRuntimeHandle:
    conn: sqlite3.Connection
    service: SQLiteV1Service
    server: ThreadingHTTPServer
    config: ServiceRuntimeConfig
    endpoint: str

    def close(self) -> None:
        self.server.server_close()
        self.conn.close()


def prepare_service_runtime(
    config: ServiceRuntimeConfig,
    *,
    clock: Callable[[], datetime] | None = None,
) -> ServiceRuntimeHandle:
    db_path = config.sqlite_db_path.expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        service = SQLiteV1Service(conn)
        key_repository = SQLiteLocalKeyRepository(conn)
        metrics = Metrics() if config.metrics else None
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
        )
    except Exception:
        conn.close()
        raise

    host, port = server.server_address
    return ServiceRuntimeHandle(
        conn=conn,
        service=service,
        server=server,
        config=config,
        endpoint=f"http://{host}:{port}",
    )


def render_service_runtime_banner(handle: ServiceRuntimeHandle) -> str:
    return "\n".join(
        [
            "# Vinctor service listening",
            f"# URL: {handle.endpoint}",
            f"# mode: {handle.config.service_mode}",
            f"# database: {handle.config.sqlite_db_path}",
            f"# log_level: {handle.config.log_level}",
            "# Local/self-hostable prototype only; not a hosted production service.",
            "# This command does not print raw keys. Bootstrap keys separately when needed.",
            "# Press Ctrl+C to stop.",
        ]
    )


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
