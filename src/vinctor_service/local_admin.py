from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit

from vinctor_service.sqlite import SQLiteV1Service
from vinctor_service.sqlite_txn import connect_sqlite


class LocalAdminError(Exception):
    pass


def run_local_admin(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parser = _parser()
    args = parser.parse_args(argv)

    try:
        _dispatch(args, stdout=stdout)
    except LocalAdminError as error:
        print(f"error: {error}", file=stderr)
        return 2
    return 0


def main(argv: list[str] | None = None) -> None:
    raise SystemExit(run_local_admin(argv))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Operate a local Vinctor prototype service.",
    )
    parser.add_argument(
        "--endpoint",
        default=os.environ.get("VINCTOR_ENDPOINT"),
        help="Local service endpoint. Defaults to VINCTOR_ENDPOINT.",
    )
    parser.add_argument(
        "--workspace-key",
        default=os.environ.get("VINCTOR_WORKSPACE_KEY"),
        help="Workspace/admin key. Defaults to VINCTOR_WORKSPACE_KEY.",
    )
    parser.add_argument(
        "--agent-key",
        default=os.environ.get("VINCTOR_AGENT_KEY"),
        help="Agent key. Defaults to VINCTOR_AGENT_KEY.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(os.environ["VINCTOR_DB"]) if "VINCTOR_DB" in os.environ else None,
        help="SQLite database path for local DB-only commands.",
    )
    parser.add_argument("--workspace-id", default="ws_local")
    parser.add_argument("--agent-id", default="agent_local")

    commands = parser.add_subparsers(dest="command", required=True)
    _add_grant_request_commands(commands)
    _add_rule_commands(commands)
    _add_bounds_commands(commands)
    _add_audit_command(commands)
    _add_enforce_command(commands)
    return parser


def _add_grant_request_commands(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser("grant-requests", help="Create and decide grant requests.")
    subcommands = parser.add_subparsers(dest="grant_requests_command", required=True)

    create = subcommands.add_parser("create")
    create.add_argument("--scope", action="append", dest="scopes", required=True)
    create.add_argument("--ttl-seconds", required=True, type=int)
    create.add_argument("--reason", required=True)

    subcommands.add_parser("list")

    approve = subcommands.add_parser("approve")
    approve.add_argument("request_id")
    approve.add_argument("--reason")

    reject = subcommands.add_parser("reject")
    reject.add_argument("request_id")
    reject.add_argument("--reason")

    auto_approve = subcommands.add_parser("auto-approve")
    auto_approve.add_argument("request_id")


def _add_rule_commands(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser(
        "auto-approval-rules",
        help="Manage local auto-approval rules.",
    )
    subcommands = parser.add_subparsers(dest="rule_command", required=True)

    create = subcommands.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--target-agent-id", required=True)
    create.add_argument("--scope", action="append", dest="scopes", required=True)
    create.add_argument("--max-ttl-seconds", required=True, type=int)

    subcommands.add_parser("list")

    disable = subcommands.add_parser("disable")
    disable.add_argument("rule_id")


def _add_bounds_commands(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser(
        "bounds",
        help="Set or inspect local agent issuable scope bounds.",
    )
    subcommands = parser.add_subparsers(dest="bounds_command", required=True)

    set_bounds = subcommands.add_parser("set")
    set_bounds.add_argument("--scope", action="append", dest="scopes", required=True)

    subcommands.add_parser("show")


def _add_audit_command(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser("audit", help="Show recent local audit events.")
    parser.add_argument("--limit", type=int, default=20)


def _add_enforce_command(commands: argparse._SubParsersAction) -> None:
    parser = commands.add_parser("enforce", help="Send a local enforce check.")
    parser.add_argument("--grant-ref", default=os.environ.get("VINCTOR_GRANT_REF"))
    parser.add_argument("--action", required=True)
    parser.add_argument("--resource", required=True)
    parser.add_argument("--boundary-id", default=os.environ.get("VINCTOR_BOUNDARY_ID"))


def _dispatch(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.command == "grant-requests":
        _grant_requests(args, stdout=stdout)
        return
    if args.command == "auto-approval-rules":
        _auto_approval_rules(args, stdout=stdout)
        return
    if args.command == "bounds":
        _bounds(args, stdout=stdout)
        return
    if args.command == "audit":
        _audit(args, stdout=stdout)
        return
    if args.command == "enforce":
        _enforce(args, stdout=stdout)
        return
    raise LocalAdminError(f"unknown command: {args.command}")


def _grant_requests(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.grant_requests_command
    if command == "create":
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/grant-requests",
            headers={"X-Agent-Key": _require(args.agent_key, "agent key")},
            body={
                "scopes": args.scopes,
                "ttl_seconds": args.ttl_seconds,
                "reason": args.reason,
            },
        )
        _raise_for_status(status, body)
        print(
            "created grant_request "
            f"{body['request_id']} status={body['status']} "
            f"routing={body.get('routing_hint', '-')} scopes={_scopes(body)}",
            file=stdout,
        )
        return

    if command == "list":
        status, body = _request_json(
            args.endpoint,
            "GET",
            "/v1/grant-requests",
            headers={"X-Workspace-Key": _require(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _print_grant_requests(body["grant_requests"], stdout=stdout)
        return

    if command in {"approve", "reject"}:
        payload = {"decision_reason": args.reason} if args.reason is not None else None
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grant-requests/{args.request_id}/{command}",
            headers={"X-Workspace-Key": _require(args.workspace_key, "workspace key")},
            body=payload,
        )
        _raise_for_status(status, body)
        _print_decision(command, body, stdout=stdout)
        return

    if command == "auto-approve":
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grant-requests/{args.request_id}/auto-approve",
            headers={"X-Workspace-Key": _require(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        auto_approval = body.get("auto_approval", {})
        if auto_approval.get("decision") == "approved":
            print(
                "auto-approved grant_request "
                f"{body['request_id']} grant_ref={body['issued_grant_ref']} "
                f"rule={auto_approval.get('rule_id')}",
                file=stdout,
            )
        else:
            print(
                "pending grant_request "
                f"{body['request_id']} auto_approval={auto_approval.get('reason')}",
                file=stdout,
            )
        return

    raise LocalAdminError(f"unknown grant-requests command: {command}")


def _auto_approval_rules(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.rule_command
    if command == "create":
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/auto-approval-rules",
            headers={"X-Workspace-Key": _require(args.workspace_key, "workspace key")},
            body={
                "name": args.name,
                "target_agent_id": args.target_agent_id,
                "allowed_scopes": args.scopes,
                "max_ttl_seconds": args.max_ttl_seconds,
            },
        )
        _raise_for_status(status, body)
        print(
            "created auto_approval_rule "
            f"{body['rule_id']} status={body['status']} scopes={_scopes(body, 'allowed_scopes')}",
            file=stdout,
        )
        return

    if command == "list":
        status, body = _request_json(
            args.endpoint,
            "GET",
            "/v1/auto-approval-rules",
            headers={"X-Workspace-Key": _require(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _print_rules(body["auto_approval_rules"], stdout=stdout)
        return

    if command == "disable":
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/auto-approval-rules/{args.rule_id}/disable",
            headers={"X-Workspace-Key": _require(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        print(
            f"disabled auto_approval_rule {body['rule_id']} status={body['status']}",
            file=stdout,
        )
        return

    raise LocalAdminError(f"unknown auto-approval-rules command: {command}")


def _bounds(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    if args.bounds_command == "set":
        service.set_agent_issuable_scope_bounds(
            workspace_id=args.workspace_id,
            agent_id=args.agent_id,
            scopes=tuple(args.scopes),
            now=datetime.now(UTC),
            enforcing_principal=f"workspace:{args.workspace_id}",
        )
        print(
            f"set bounds workspace={args.workspace_id} agent={args.agent_id} "
            f"scopes={','.join(args.scopes)}",
            file=stdout,
        )
        return

    if args.bounds_command == "show":
        scopes = service.scope_bounds_repository.get_bounds(
            workspace_id=args.workspace_id,
            agent_id=args.agent_id,
        )
        if scopes is None:
            print(f"no bounds workspace={args.workspace_id} agent={args.agent_id}", file=stdout)
        else:
            print(
                f"bounds workspace={args.workspace_id} agent={args.agent_id} "
                f"scopes={','.join(scopes)}",
                file=stdout,
            )
        return

    raise LocalAdminError(f"unknown bounds command: {args.bounds_command}")


def _audit(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.limit <= 0:
        raise LocalAdminError("audit --limit must be positive")
    service = _sqlite_service(args.db)
    events = service.audit_events[-args.limit :]
    if not events:
        print("no audit events", file=stdout)
        return
    for event in events:
        print(
            f"{event.created_at.isoformat()} {event.event_type} "
            f"decision={event.decision} reason={event.reason} "
            f"agent={event.agent_id} grant_ref={event.grant_ref} "
            f"action={event.action} resource={event.resource} "
            f"scope={event.scope_matched or '-'} boundary={event.boundary_id or '-'}",
            file=stdout,
        )


def _enforce(args: argparse.Namespace, *, stdout: TextIO) -> None:
    grant_ref = _require(args.grant_ref, "grant ref")
    headers = {"X-Agent-Key": _require(args.agent_key, "agent key")}
    if args.boundary_id:
        headers["X-Vinctor-Boundary-Id"] = args.boundary_id
    status, body = _request_json(
        args.endpoint,
        "POST",
        "/v1/enforce",
        headers=headers,
        body={
            "grant_ref": grant_ref,
            "action": args.action,
            "resource": args.resource,
        },
    )
    _raise_for_status(status, body)
    print(
        f"{body['decision']} action={args.action} resource={args.resource} "
        f"audit_event_id={body.get('audit_event_id')}",
        file=stdout,
    )


def _request_json(
    endpoint: str | None,
    method: str,
    path: str,
    *,
    headers: dict[str, str],
    body: object | None = None,
) -> tuple[int, dict[str, object]]:
    endpoint_value = _require(endpoint, "endpoint")
    parsed = urlsplit(endpoint_value)
    if parsed.scheme != "http" or parsed.hostname is None or parsed.port is None:
        raise LocalAdminError("endpoint must look like http://127.0.0.1:8765")

    request_headers = dict(headers)
    request_body = None
    if body is not None:
        request_headers["Content-Type"] = "application/json"
        request_body = json.dumps(body)

    conn = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        conn.request(method, path, body=request_body, headers=request_headers)
        response = conn.getresponse()
        response_text = response.read().decode("utf-8")
    finally:
        conn.close()

    try:
        response_body = json.loads(response_text) if response_text else {}
    except json.JSONDecodeError as error:
        raise LocalAdminError(f"service returned non-JSON response: {response_text}") from error
    if not isinstance(response_body, dict):
        raise LocalAdminError("service returned non-object JSON response")
    return response.status, response_body


def _sqlite_service(db_path: Path | None) -> SQLiteV1Service:
    db = _require(db_path, "database path")
    conn = connect_sqlite(str(Path(db)))
    return SQLiteV1Service(conn)


def _require(value, name: str):
    if value is None or value == "":
        raise LocalAdminError(f"{name} is required")
    return value


def _raise_for_status(status: int, body: dict[str, object]) -> None:
    if status < 400:
        return
    error = body.get("error", "request_failed")
    reason = body.get("reason", error)
    raise LocalAdminError(f"{status} {error}: {reason}")


def _print_grant_requests(
    requests: list[object],
    *,
    stdout: TextIO,
) -> None:
    if not requests:
        print("no grant requests", file=stdout)
        return
    for request in requests:
        if not isinstance(request, dict):
            continue
        print(
            f"{request['request_id']} status={request['status']} "
            f"requester={request['requester_agent_id']} target={request['target_agent_id']} "
            f"ttl={request['requested_ttl_seconds']} scopes={_scopes(request, 'requested_scopes')} "
            f"issued={request.get('issued_grant_ref') or '-'} reason={request['reason']}",
            file=stdout,
        )


def _print_rules(rules: list[object], *, stdout: TextIO) -> None:
    if not rules:
        print("no auto-approval rules", file=stdout)
        return
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        print(
            f"{rule['rule_id']} status={rule['status']} target={rule['target_agent_id']} "
            f"max_ttl={rule['max_ttl_seconds']} scopes={_scopes(rule, 'allowed_scopes')} "
            f"name={rule['name']}",
            file=stdout,
        )


def _print_decision(command: str, body: dict[str, object], *, stdout: TextIO) -> None:
    grant = body.get("grant")
    grant_ref = grant.get("grant_ref") if isinstance(grant, dict) else body.get("issued_grant_ref")
    verb = "approved" if command == "approve" else "rejected"
    print(
        f"{verb} grant_request {body['request_id']} status={body['status']} "
        f"grant_ref={grant_ref or '-'}",
        file=stdout,
    )


def _scopes(body: dict[str, object], key: str = "requested_scopes") -> str:
    value = body.get(key, [])
    if not isinstance(value, list):
        return "-"
    return ",".join(str(scope) for scope in value)


if __name__ == "__main__":
    main()
