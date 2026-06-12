from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from time import sleep
from typing import Any, NamedTuple, TextIO

from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_http import create_v1_http_server
from vinctor_service.sqlite import SQLiteV1Service

DEFAULT_SCOPES = ("write:repo/design-partner/feature/*", "execute:ci/test")


class E2EConfig(NamedTuple):
    db_path: Path
    host: str = "127.0.0.1"
    port: int = 8765
    workspace_id: str = "ws_design_partner"
    agent_id: str = "agent_claude_code"
    scopes: tuple[str, ...] = DEFAULT_SCOPES
    grant_ttl_seconds: int = 86_400
    workspace_key: str | None = None
    agent_key: str | None = None
    boundary_name: str = "claude-code-2.1.169"
    boundary_runtime: str = "claude-code"
    boundary_type: str = "pretooluse"
    permit_action: str = "write"
    permit_resource: str = "repo/design-partner/feature/README.md"
    deny_action: str = "write"
    deny_resource: str = "repo/design-partner/protected/README.md"
    hook_cli: Path | None = None
    hook_config_path: Path | None = None


class E2EHandle(NamedTuple):
    conn: sqlite3.Connection
    service: SQLiteV1Service
    server: object
    thread: Thread
    db_path: Path
    endpoint: str
    workspace_id: str
    agent_id: str
    workspace_key: str
    agent_key: str
    grant_ref: str
    boundary_id: str | None
    boundary_runtime: str | None
    boundary_type: str | None
    hook_cli: Path | None
    hook_config_path: Path


def prepare_design_partner_e2e(
    config: E2EConfig,
    *,
    now: datetime | None = None,
) -> E2EHandle:
    timestamp = now or datetime.now(UTC)
    db_path = config.db_path.expanduser()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    hook_config_path = _write_hook_config(config, db_path=db_path)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        service = SQLiteV1Service(conn)
        service.set_agent_issuable_scope_bounds(
            workspace_id=config.workspace_id,
            agent_id=config.agent_id,
            scopes=config.scopes,
            now=timestamp,
        )
        key_repository = SQLiteLocalKeyRepository(conn)
        workspace_key = _workspace_key(key_repository, config, timestamp)
        agent_key = _agent_key(key_repository, config, timestamp)
        server = create_v1_http_server(
            (config.host, config.port),
            service=service,
            agent_identities={},
            workspace_identities={},
            agent_identity_resolver=lambda raw_key, used_at: (
                key_repository.resolve_agent_identity(raw_key, now=used_at)
            ),
            workspace_identity_resolver=lambda raw_key, used_at: (
                key_repository.resolve_workspace_identity(raw_key, now=used_at)
            ),
            clock=(lambda: timestamp) if now is not None else None,
            service_mode="local",
        )
    except Exception:
        conn.close()
        raise

    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    endpoint = f"http://{host}:{port}"

    try:
        boundary = _create_boundary(endpoint, workspace_key, config)
        grant = _issue_grant(endpoint, workspace_key, config)
    except Exception:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        conn.close()
        raise

    return E2EHandle(
        conn=conn,
        service=service,
        server=server,
        thread=thread,
        db_path=db_path,
        endpoint=endpoint,
        workspace_id=config.workspace_id,
        agent_id=config.agent_id,
        workspace_key=workspace_key,
        agent_key=agent_key,
        grant_ref=_require_string(grant, "grant_ref"),
        boundary_id=_optional_string(boundary.get("boundary_id")),
        boundary_runtime=_optional_string(boundary.get("runtime")),
        boundary_type=_optional_string(boundary.get("boundary_type")),
        hook_cli=config.hook_cli,
        hook_config_path=hook_config_path,
    )


def close_design_partner_e2e(handle: E2EHandle) -> None:
    handle.server.shutdown()
    handle.thread.join(timeout=5)
    handle.server.server_close()
    handle.conn.close()


def enforce(handle: E2EHandle, *, action: str, resource: str) -> tuple[int, dict[str, Any]]:
    headers = {"X-Agent-Key": handle.agent_key}
    if handle.boundary_id is not None:
        headers["X-Vinctor-Boundary-Id"] = handle.boundary_id
    return _request_json(
        handle.endpoint,
        "POST",
        "/v1/enforce",
        headers=headers,
        body={
            "grant_ref": handle.grant_ref,
            "action": action,
            "resource": resource,
        },
    )


def list_audit_events(handle: E2EHandle) -> tuple[int, dict[str, Any]]:
    return _request_json(
        handle.endpoint,
        "GET",
        f"/v1/audit-events?grant_ref={handle.grant_ref}&limit=20",
        headers={"X-Workspace-Key": handle.workspace_key},
    )


def run_automated_proof(
    config: E2EConfig,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    handle = prepare_design_partner_e2e(config, now=now)
    try:
        permit_status, permit = enforce(
            handle,
            action=config.permit_action,
            resource=config.permit_resource,
        )
        deny_status, deny = enforce(
            handle,
            action=config.deny_action,
            resource=config.deny_resource,
        )
        audit_status, audit = list_audit_events(handle)
        if permit_status != 200 or permit.get("decision") != "permit":
            raise RuntimeError(f"permit enforce failed status={permit_status} body={permit}")
        if deny_status != 403 or deny.get("decision") != "deny":
            raise RuntimeError(f"deny enforce failed status={deny_status} body={deny}")
        if audit_status != 200:
            raise RuntimeError(f"audit lookup failed status={audit_status} body={audit}")
        events = audit.get("audit_events")
        if not isinstance(events, list):
            raise RuntimeError("audit lookup did not return audit_events")
        event_types = [
            event.get("event_type")
            for event in events
            if isinstance(event, dict) and isinstance(event.get("event_type"), str)
        ]
        return {
            "endpoint": handle.endpoint,
            "db_path": str(handle.db_path),
            "workspace_id": handle.workspace_id,
            "agent_id": handle.agent_id,
            "grant_ref": handle.grant_ref,
            "grant_issued_via": "POST /v1/grants",
            "hook_config_path": str(handle.hook_config_path),
            "boundary_id": handle.boundary_id,
            "boundary_runtime": handle.boundary_runtime,
            "boundary_type": handle.boundary_type,
            "permit_decision": permit["decision"],
            "permit_audit_event_id": permit.get("audit_event_id"),
            "deny_decision": deny["decision"],
            "deny_reason": deny.get("error"),
            "deny_audit_event_id": deny.get("audit_event_id"),
            "audit_event_types": event_types,
        }
    finally:
        close_design_partner_e2e(handle)


def render_operator_instructions(handle: E2EHandle) -> str:
    hook_command = str(handle.hook_cli or Path("/absolute/path/to/dist/src/cli.js"))
    settings = {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": hook_command,
                        }
                    ],
                }
            ]
        }
    }
    lines = [
        "# Vinctor Claude Code design-partner E2E setup",
        f"export VINCTOR_ENDPOINT={_quote(handle.endpoint)}",
        f"export VINCTOR_AGENT_KEY={_quote(handle.agent_key)}",
        f"export VINCTOR_GRANT_REF={_quote(handle.grant_ref)}",
        f"export VINCTOR_WORKSPACE_KEY={_quote(handle.workspace_key)}",
        f"export VINCTOR_CLAUDE_CODE_HOOK_CONFIG={_quote(str(handle.hook_config_path))}",
    ]
    if handle.boundary_id is not None:
        lines.append(f"export VINCTOR_BOUNDARY_ID={_quote(handle.boundary_id)}")
    lines.extend(
        [
            "",
            f"# Hook config written to: {handle.hook_config_path}",
            "# Add this to the Claude Code workspace settings.json:",
            json.dumps(settings, indent=2, sort_keys=True),
            "",
            "# Store raw keys outside the repository; SQLite stores key hashes only.",
            "# Keep this process running while you perform the Claude Code session.",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None) -> int:
    out = stdout if stdout is not None else __import__("sys").stdout
    args = _parser().parse_args(argv)
    config = E2EConfig(
        db_path=args.db,
        host=args.host,
        port=args.port,
        workspace_id=args.workspace_id,
        agent_id=args.agent_id,
        scopes=tuple(args.scope or DEFAULT_SCOPES),
        grant_ttl_seconds=args.grant_ttl_seconds,
        workspace_key=args.workspace_key,
        agent_key=args.agent_key,
        boundary_name=args.boundary_name,
        permit_action=args.permit_action,
        permit_resource=args.permit_resource,
        deny_action=args.deny_action,
        deny_resource=args.deny_resource,
        hook_cli=args.hook_cli,
        hook_config_path=args.hook_config,
    )
    if args.serve:
        handle = prepare_design_partner_e2e(config)
        print(render_operator_instructions(handle), file=out, flush=True)
        try:
            while True:
                sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            close_design_partner_e2e(handle)
        return 0

    result = run_automated_proof(config)
    print(json.dumps(result, indent=2, sort_keys=True), file=out)
    print("ALL CLAUDE CODE DESIGN-PARTNER SETUP STEPS PASSED", file=out)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare a local Vinctor service for Claude Code E2E proof.",
    )
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--workspace-id", default="ws_design_partner")
    parser.add_argument("--agent-id", default="agent_claude_code")
    parser.add_argument("--workspace-key")
    parser.add_argument("--agent-key")
    parser.add_argument("--scope", action="append")
    parser.add_argument("--grant-ttl-seconds", type=int, default=86_400)
    parser.add_argument("--boundary-name", default="claude-code-2.1.169")
    parser.add_argument("--hook-cli", type=Path)
    parser.add_argument("--hook-config", type=Path)
    parser.add_argument("--permit-action", default="write")
    parser.add_argument("--permit-resource", default="repo/design-partner/feature/README.md")
    parser.add_argument("--deny-action", default="write")
    parser.add_argument("--deny-resource", default="repo/design-partner/protected/README.md")
    parser.add_argument("--serve", action="store_true")
    return parser


def _write_hook_config(config: E2EConfig, *, db_path: Path) -> Path:
    path = (config.hook_config_path or db_path.parent / "claude-code-hook.json").expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "version": 1,
        "rules": _hook_config_rules(config),
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return path


def _hook_config_rules(config: E2EConfig) -> list[dict[str, str | int]]:
    return [
        {
            "tool": "Write",
            "matchType": "glob",
            "pattern": "**/repo/design-partner/feature/**",
            "action": "write",
            "resource": config.permit_resource,
        },
        {
            "tool": "Edit",
            "matchType": "glob",
            "pattern": "**/repo/design-partner/feature/**",
            "action": "write",
            "resource": config.permit_resource,
        },
        {
            "tool": "Write",
            "matchType": "glob",
            "pattern": "**/repo/design-partner/protected/**",
            "action": "write",
            "resource": config.deny_resource,
        },
        {
            "tool": "Edit",
            "matchType": "glob",
            "pattern": "**/repo/design-partner/protected/**",
            "action": "write",
            "resource": config.deny_resource,
        },
        {
            "tool": "Read",
            "matchType": "glob",
            "pattern": "**/repo/design-partner/protected/**",
            "action": "read",
            "resource": config.deny_resource,
        },
        {
            "tool": "Bash",
            "matchType": "exact",
            "pattern": "echo test-ok",
            "action": "execute",
            "resource": "ci/test",
        },
    ]


def _workspace_key(
    repository: SQLiteLocalKeyRepository,
    config: E2EConfig,
    now: datetime,
) -> str:
    if config.workspace_key is not None:
        repository.ensure_workspace_key(
            workspace_id=config.workspace_id,
            raw_key=config.workspace_key,
            now=now,
        )
        return config.workspace_key
    return repository.create_workspace_key(workspace_id=config.workspace_id, now=now).raw_key


def _agent_key(
    repository: SQLiteLocalKeyRepository,
    config: E2EConfig,
    now: datetime,
) -> str:
    if config.agent_key is not None:
        repository.ensure_agent_key(
            workspace_id=config.workspace_id,
            agent_id=config.agent_id,
            raw_key=config.agent_key,
            now=now,
        )
        return config.agent_key
    return repository.create_agent_key(
        workspace_id=config.workspace_id,
        agent_id=config.agent_id,
        now=now,
    ).raw_key


def _create_boundary(
    endpoint: str,
    workspace_key: str,
    config: E2EConfig,
) -> dict[str, Any]:
    status, body = _request_json(
        endpoint,
        "POST",
        "/v1/boundaries",
        headers={"X-Workspace-Key": workspace_key},
        body={
            "name": config.boundary_name,
            "runtime": config.boundary_runtime,
            "boundary_type": config.boundary_type,
            "mode": "fail_closed",
        },
    )
    if status != 201:
        raise RuntimeError(f"boundary registration failed status={status} body={body}")
    return body


def _issue_grant(endpoint: str, workspace_key: str, config: E2EConfig) -> dict[str, Any]:
    status, body = _request_json(
        endpoint,
        "POST",
        "/v1/grants",
        headers={"X-Workspace-Key": workspace_key},
        body={
            "agent_id": config.agent_id,
            "scopes": list(config.scopes),
            "ttl_seconds": config.grant_ttl_seconds,
        },
    )
    if status != 201:
        raise RuntimeError(f"grant issue failed status={status} body={body}")
    return body


def _request_json(
    endpoint: str,
    method: str,
    path: str,
    *,
    headers: dict[str, str],
    body: object | None = None,
) -> tuple[int, dict[str, Any]]:
    host, port = _endpoint_host_port(endpoint)
    conn = HTTPConnection(host, port, timeout=5)
    try:
        request_headers = {"Content-Type": "application/json", **headers}
        conn.request(
            method,
            path,
            body=None if body is None else json.dumps(body),
            headers=request_headers,
        )
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
    finally:
        conn.close()
    decoded = json.loads(raw)
    if not isinstance(decoded, dict):
        raise RuntimeError("response was not a JSON object")
    return response.status, decoded


def _endpoint_host_port(endpoint: str) -> tuple[str, int]:
    if not endpoint.startswith("http://"):
        raise ValueError("local E2E setup uses http:// endpoints only")
    host_port = endpoint.removeprefix("http://")
    host, port_text = host_port.rsplit(":", 1)
    return host, int(port_text)


def _require_string(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str) or value == "":
        raise RuntimeError(f"response missing string field: {key}")
    return value


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


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
    raise SystemExit(main())
