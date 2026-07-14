from __future__ import annotations

import argparse
import errno
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
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
from vinctor_service.models import GrantIssueRequest
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
    db_path: Path
    endpoint: str
    workspace_key: str
    agent_key: str
    grant_ref: str
    grant_expires_at: datetime | None
    generated_workspace_key: bool
    generated_agent_key: bool
    boundary: Boundary | None = None

    def close(self) -> None:
        self.server.server_close()
        close_export = getattr(self.service.audit_writer, "close_export", None)
        if callable(close_export):
            close_export()
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
        grant = _ensure_grant(service, config, now=timestamp)
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
            pep_identity_resolver=lambda raw_key, used_at: key_repository.resolve_pep_identity(
                raw_key, now=used_at
            ),
            clock=(lambda: timestamp) if now is not None else None,
        )
    except Exception:
        conn.close()
        raise

    host, port = server.server_address
    return LocalServiceHandle(
        conn=conn,
        service=service,
        server=server,
        db_path=db_path,
        endpoint=f"http://{host}:{port}",
        workspace_key=workspace_key,
        agent_key=agent_key,
        grant_ref=config.grant_ref,
        grant_expires_at=grant.expires_at,
        generated_workspace_key=config.workspace_key is None,
        generated_agent_key=config.agent_key is None,
        boundary=boundary,
    )


def render_env_exports(
    handle: LocalServiceHandle,
    *,
    now: datetime | None = None,
) -> str:
    timestamp = now or datetime.now(UTC)
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
    if handle.grant_expires_at is not None:
        lines.append(f"# Grant expires at {handle.grant_expires_at.isoformat()}.")
        if handle.grant_expires_at <= timestamp:
            lines.append(
                "# WARNING: this grant is expired; /v1/enforce will deny until "
                "you use a fresh grant or database."
            )
    if handle.generated_workspace_key or handle.generated_agent_key:
        lines.append("# Store these raw keys outside the repo; SQLite stores hashes only.")
    lines.extend(_restart_command_lines(handle))
    return "\n".join(lines)


def serve_local_service(config: LocalLaunchConfig) -> NoReturn:
    try:
        handle = prepare_local_service(config)
    except OSError as error:
        if error.errno == errno.EADDRINUSE:
            from vinctor_service.cli import EXIT_SERVICE, CliError

            raise CliError(
                f"port {config.port} already in use — pass --port <n> "
                "(or --port 0 for any free port)",
                code=EXIT_SERVICE,
            ) from error
        raise
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
    parser.add_argument("--host", default="127.0.0.1", help="Local bind host.")
    parser.add_argument(
        "--port",
        default=8765,
        type=int,
        help="Local bind port. Use 0 for any free port.",
    )
    parser.add_argument(
        "--workspace-id",
        default="ws_local",
        help="Workspace id for bootstrapped local records.",
    )
    parser.add_argument(
        "--agent-id",
        default="agent_local",
        help="Agent id bound to the local enforce key.",
    )
    parser.add_argument(
        "--workspace-key",
        help="Existing wsk_ key to reuse for workspace/admin routes.",
    )
    parser.add_argument("--agent-key", help="Existing aak_ key to reuse for /v1/enforce.")
    parser.add_argument(
        "--grant-id",
        help="Optional grant id to use when creating a new local grant.",
    )
    parser.add_argument(
        "--grant-ref",
        default="grt_local",
        help="Grant ref sent in the strict /v1/enforce body.",
    )
    parser.add_argument(
        "--scope",
        action="append",
        dest="scopes",
        help="Grant scope such as write:repo/feature/*. Repeatable.",
    )
    parser.add_argument(
        "--grant-ttl-hours",
        default=8,
        type=int,
        help="TTL in hours for newly created local grants.",
    )
    parser.add_argument("--boundary-name", help="Optional local boundary name to create or reuse.")
    parser.add_argument("--boundary-runtime", default="claude-code", help="Boundary runtime label.")
    parser.add_argument("--boundary-type", default="pretooluse", help="Boundary type label.")
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
    service.set_agent_issuable_scope_bounds(
        workspace_id=config.workspace_id,
        agent_id=config.agent_id,
        scopes=config.scopes,
        now=now,
    )
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

    result = service.issue_grant(
        GrantIssueRequest(
            workspace_id=config.workspace_id,
            target_agent_id=config.agent_id,
            requested_scopes=config.scopes,
            ttl_seconds=config.grant_ttl_hours * 60 * 60,
            grant_id=config.grant_id,
            grant_ref=config.grant_ref,
        ),
        now=now,
    )
    if result.status == "rejected" or result.grant is None:
        raise ValueError(f"could not issue local grant: {result.reason}")
    return result.grant


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


def _restart_command_lines(handle: LocalServiceHandle) -> list[str]:
    lines = [
        "# Restart with explicit keys:",
        "# vinctor local start \\",
        f"#   --db {_quote(str(handle.db_path))} \\",
        '#   --workspace-key "$VINCTOR_WORKSPACE_KEY" \\',
        '#   --agent-key "$VINCTOR_AGENT_KEY" \\',
        '#   --grant-ref "$VINCTOR_GRANT_REF"',
    ]
    if handle.boundary is not None:
        lines[-1] += " \\"
        lines.append(f"#   --boundary-name {_quote(handle.boundary.name)}")
    lines.append("# fallback: python -m vinctor_service.local_launcher ...")
    return lines


def _new_id(prefix: str) -> str:
    return f"{prefix}_{token_urlsafe(16)}"


def _quote(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
        .replace("\n", "\\n")
    )
    return f'"{escaped}"'


if __name__ == "__main__":
    main()
