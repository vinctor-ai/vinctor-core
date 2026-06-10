from __future__ import annotations

import argparse
import shlex
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from pathlib import Path
from secrets import token_urlsafe
from typing import NoReturn

from vinctor_core.models import Boundary, BoundaryRegistrationInput, Grant
from vinctor_core.scope import is_valid_grant_scope
from vinctor_service.keys import (
    AGENT_KEY_PREFIX,
    WORKSPACE_KEY_PREFIX,
    CreatedLocalKey,
    SQLiteLocalKeyRepository,
)
from vinctor_service.local_http import create_v1_http_server
from vinctor_service.sqlite import SQLiteV1Service

DEFAULT_SCOPE = "write:repo/feature/*"


@dataclass(frozen=True)
class LocalLaunchConfig:
    db_path: Path
    host: str = "127.0.0.1"
    port: int = 8765
    workspace_id: str = "ws_local"
    agent_id: str = "agent_local"
    workspace_key: str | None = None
    agent_key: str | None = None
    grant_id: str | None = None
    grant_ref: str = "grt_local"
    scopes: tuple[str, ...] = (DEFAULT_SCOPE,)
    grant_ttl_hours: int = 8
    boundary_name: str | None = None
    boundary_runtime: str = "claude-code"
    boundary_type: str = "pretooluse"


@dataclass
class LocalServiceHandle:
    conn: sqlite3.Connection
    service: SQLiteV1Service
    server: ThreadingHTTPServer
    endpoint: str
    workspace_key: str
    agent_key: str
    grant_ref: str
    boundary: Boundary | None = None

    def close(self) -> None:
        self.server.server_close()
        self.conn.close()


def prepare_local_service(
    config: LocalLaunchConfig,
    *,
    now: datetime | None = None,
) -> LocalServiceHandle:
    timestamp = now or datetime.now(UTC)
    _validate_config(config)
    db_path = config.db_path.expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)

    try:
        service = SQLiteV1Service(conn)
        _ensure_grant(service, config, now=timestamp)
        boundary = _ensure_boundary(service, config, now=timestamp)
        key_repository = SQLiteLocalKeyRepository(conn)
        workspace_key = _ensure_workspace_key(
            key_repository,
            config,
            now=timestamp,
        )
        agent_key = _ensure_agent_key(
            key_repository,
            config,
            now=timestamp,
        )
        agent_resolver = key_repository.resolve_agent_identity
        workspace_resolver = key_repository.resolve_workspace_identity
        server = create_v1_http_server(
            (config.host, config.port),
            service=service,
            agent_identities={},
            workspace_identities={},
            agent_identity_resolver=lambda raw_key, used_at: agent_resolver(
                raw_key,
                now=used_at,
            ),
            workspace_identity_resolver=lambda raw_key, used_at: workspace_resolver(
                raw_key,
                now=used_at,
            ),
        )
    except Exception:
        conn.close()
        raise

    host, port = server.server_address
    return LocalServiceHandle(
        conn=conn,
        service=service,
        server=server,
        endpoint=f"http://{host}:{port}",
        workspace_key=workspace_key,
        agent_key=agent_key,
        grant_ref=config.grant_ref,
        boundary=boundary,
    )


def render_env_exports(handle: LocalServiceHandle) -> str:
    lines = [
        "# Vinctor local service exports",
        f"export VINCTOR_ENDPOINT={_quote(handle.endpoint)}",
        f"export VINCTOR_AGENT_KEY={_quote(handle.agent_key)}",
        f"export VINCTOR_GRANT_REF={_quote(handle.grant_ref)}",
        f"export VINCTOR_WORKSPACE_KEY={_quote(handle.workspace_key)}",
    ]
    if handle.boundary is not None:
        lines.extend(
            [
                f"export VINCTOR_BOUNDARY_ID={_quote(handle.boundary.boundary_id)}",
                "# Use VINCTOR_BOUNDARY_ID as the X-Vinctor-Boundary-Id header.",
            ]
        )
    return "\n".join(lines)


def serve_local_service(config: LocalLaunchConfig) -> NoReturn:
    handle = prepare_local_service(config)
    print(render_env_exports(handle), flush=True)
    print("# Local Vinctor service listening. Press Ctrl+C to stop.", flush=True)
    try:
        handle.server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()
    raise SystemExit(0)


def main(argv: list[str] | None = None) -> None:
    serve_local_service(_parse_args(argv))


def _parse_args(argv: list[str] | None) -> LocalLaunchConfig:
    parser = argparse.ArgumentParser(
        description="Run a local prototype Vinctor service.",
    )
    parser.add_argument("--db", required=True, type=Path, help="SQLite database path.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8765, type=int)
    parser.add_argument("--workspace-id", default="ws_local")
    parser.add_argument("--agent-id", default="agent_local")
    parser.add_argument("--workspace-key")
    parser.add_argument("--agent-key")
    parser.add_argument("--grant-id")
    parser.add_argument("--grant-ref", default="grt_local")
    parser.add_argument("--scope", action="append", dest="scopes")
    parser.add_argument("--grant-ttl-hours", default=8, type=int)
    parser.add_argument("--boundary-name")
    parser.add_argument("--boundary-runtime", default="claude-code")
    parser.add_argument("--boundary-type", default="pretooluse")
    args = parser.parse_args(argv)

    return LocalLaunchConfig(
        db_path=args.db,
        host=args.host,
        port=args.port,
        workspace_id=args.workspace_id,
        agent_id=args.agent_id,
        workspace_key=args.workspace_key,
        agent_key=args.agent_key,
        grant_id=args.grant_id,
        grant_ref=args.grant_ref,
        scopes=tuple(args.scopes or [DEFAULT_SCOPE]),
        grant_ttl_hours=args.grant_ttl_hours,
        boundary_name=args.boundary_name,
        boundary_runtime=args.boundary_runtime,
        boundary_type=args.boundary_type,
    )


def _ensure_grant(
    service: SQLiteV1Service,
    config: LocalLaunchConfig,
    *,
    now: datetime,
) -> Grant:
    existing = service.grant_repository.get_by_ref(config.grant_ref)
    if existing is not None:
        if (
            existing.workspace_id != config.workspace_id
            or existing.agent_id != config.agent_id
            or existing.scopes != config.scopes
        ):
            raise ValueError(
                f"existing grant_ref has incompatible bootstrap data: {config.grant_ref}"
            )
        return existing

    grant = Grant(
        grant_id=config.grant_id or _new_id("grnt"),
        grant_ref=config.grant_ref,
        workspace_id=config.workspace_id,
        agent_id=config.agent_id,
        scopes=config.scopes,
        status="active",
        expires_at=now + timedelta(hours=config.grant_ttl_hours),
    )
    service.insert_grant(grant)
    return grant


def _ensure_boundary(
    service: SQLiteV1Service,
    config: LocalLaunchConfig,
    *,
    now: datetime,
) -> Boundary | None:
    if config.boundary_name is None:
        return None

    for boundary in service.list_boundaries(config.workspace_id):
        if boundary.name == config.boundary_name:
            if (
                boundary.runtime != config.boundary_runtime
                or boundary.boundary_type != config.boundary_type
            ):
                raise ValueError(
                    f"existing boundary has incompatible bootstrap data: {config.boundary_name}"
                )
            if boundary.status == "disabled":
                enabled = service.enable_boundary(
                    boundary_id=boundary.boundary_id,
                    workspace_id=config.workspace_id,
                    now=now,
                )
                if enabled is None:
                    raise ValueError(
                        f"boundary disappeared during bootstrap: {boundary.boundary_id}"
                    )
                return enabled
            return boundary

    return service.register_boundary(
        BoundaryRegistrationInput(
            workspace_id=config.workspace_id,
            name=config.boundary_name,
            runtime=config.boundary_runtime,
            boundary_type=config.boundary_type,
        ),
        now=now,
    )


def _ensure_workspace_key(
    key_repository: SQLiteLocalKeyRepository,
    config: LocalLaunchConfig,
    *,
    now: datetime,
) -> str:
    if config.workspace_key is not None:
        key_repository.ensure_workspace_key(
            workspace_id=config.workspace_id,
            raw_key=config.workspace_key,
            now=now,
        )
        return config.workspace_key

    created = key_repository.create_workspace_key(
        workspace_id=config.workspace_id,
        now=now,
    )
    return _raw_key(created)


def _ensure_agent_key(
    key_repository: SQLiteLocalKeyRepository,
    config: LocalLaunchConfig,
    *,
    now: datetime,
) -> str:
    if config.agent_key is not None:
        key_repository.ensure_agent_key(
            workspace_id=config.workspace_id,
            agent_id=config.agent_id,
            raw_key=config.agent_key,
            now=now,
        )
        return config.agent_key

    created = key_repository.create_agent_key(
        workspace_id=config.workspace_id,
        agent_id=config.agent_id,
        now=now,
    )
    return _raw_key(created)


def _validate_config(config: LocalLaunchConfig) -> None:
    if config.port < 0 or config.port > 65535:
        raise ValueError("port must be between 0 and 65535")
    if config.grant_ttl_hours <= 0:
        raise ValueError("grant_ttl_hours must be positive")
    if not config.scopes:
        raise ValueError("at least one scope is required")
    invalid_scopes = [scope for scope in config.scopes if not is_valid_grant_scope(scope)]
    if invalid_scopes:
        raise ValueError(f"invalid grant scope: {invalid_scopes[0]}")
    if config.workspace_key is not None and not config.workspace_key.startswith(
        WORKSPACE_KEY_PREFIX
    ):
        raise ValueError(f"workspace_key must start with {WORKSPACE_KEY_PREFIX}")
    if config.agent_key is not None and not config.agent_key.startswith(AGENT_KEY_PREFIX):
        raise ValueError(f"agent_key must start with {AGENT_KEY_PREFIX}")


def _raw_key(created: CreatedLocalKey) -> str:
    return created.raw_key


def _new_id(prefix: str) -> str:
    return f"{prefix}_{token_urlsafe(16)}"


def _quote(value: str) -> str:
    return shlex.quote(value)


if __name__ == "__main__":
    main()
