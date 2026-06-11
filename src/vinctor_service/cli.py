from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from typing import NoReturn, TextIO
from urllib.parse import urlsplit

from vinctor_core.models import Grant
from vinctor_service.local_launcher import (
    DEFAULT_SCOPE,
    LocalLaunchConfig,
    prepare_local_service,
    serve_local_service,
)
from vinctor_service.policy_files import (
    apply_policy_file,
    export_policy_document,
    write_policy_file,
)
from vinctor_service.sqlite import SQLiteV1Service

EXIT_UNEXPECTED = 1
EXIT_USAGE = 2
EXIT_DENIED = 3
EXIT_AUTH = 4
EXIT_SERVICE = 5


class CliError(Exception):
    def __init__(self, message: str, *, code: int = EXIT_USAGE):
        super().__init__(message)
        self.code = code


def run_vinctor(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        _dispatch(args, stdout=stdout)
    except CliError as error:
        _emit_error(args, error, stderr=stderr)
        return error.code
    except KeyboardInterrupt:
        print("interrupted", file=stderr)
        return EXIT_UNEXPECTED
    return 0


def main(argv: list[str] | None = None) -> NoReturn:
    raise SystemExit(run_vinctor(argv))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vinctor",
        description="Operate the local Vinctor prototype.",
    )
    parser.add_argument("--endpoint", default=os.environ.get("VINCTOR_ENDPOINT"))
    parser.add_argument("--workspace-key", default=os.environ.get("VINCTOR_WORKSPACE_KEY"))
    parser.add_argument("--agent-key", default=os.environ.get("VINCTOR_AGENT_KEY"))
    parser.add_argument("--grant-ref", default=os.environ.get("VINCTOR_GRANT_REF"))
    parser.add_argument("--boundary-id", default=os.environ.get("VINCTOR_BOUNDARY_ID"))
    parser.add_argument(
        "--db",
        type=Path,
        default=Path(os.environ["VINCTOR_DB"]) if "VINCTOR_DB" in os.environ else None,
    )
    parser.add_argument("--workspace-id", default="ws_local")
    parser.add_argument("--agent-id", default="agent_local")
    parser.add_argument("--json", action="store_true", help="Write JSON to stdout.")
    parser.add_argument("-o", "--output", choices=("text", "json"), default=None)

    roles = parser.add_subparsers(dest="role", required=True)
    _add_local_commands(roles)
    _add_agent_commands(roles)
    _add_operator_commands(roles)
    _add_demo_commands(roles)
    return parser


def _add_local_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser("local", help="Start and inspect local prototype services.")
    commands = parser.add_subparsers(dest="local_command", required=True)

    start = commands.add_parser("start", help="Start a local SQLite-backed service.")
    _add_local_start_args(start)

    commands.add_parser("env", help="Print shell exports from provided or existing env values.")


def _add_local_start_args(parser: argparse.ArgumentParser) -> None:
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


def _add_agent_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser("agent", help="Request and consume scoped grants.")
    commands = parser.add_subparsers(dest="agent_command", required=True)

    requests = commands.add_parser("requests")
    request_commands = requests.add_subparsers(dest="requests_command", required=True)
    create = request_commands.add_parser("create")
    create.add_argument("--scope", action="append", dest="scopes", required=True)
    create.add_argument("--ttl", required=True)
    create.add_argument("--reason", required=True)
    status = request_commands.add_parser("status")
    status.add_argument("request_id")

    enforce = commands.add_parser("enforce")
    enforce.add_argument("--grant-ref", dest="enforce_grant_ref")
    enforce.add_argument("--action", required=True)
    enforce.add_argument("--resource", required=True)


def _add_operator_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser("operator", help="Operate request queues, rules, bounds, and audit.")
    resources = parser.add_subparsers(dest="operator_resource", required=True)

    requests = resources.add_parser("requests")
    request_commands = requests.add_subparsers(dest="requests_command", required=True)
    list_requests = request_commands.add_parser("list")
    list_requests.add_argument(
        "--status",
        choices=("pending", "approved", "rejected", "cancelled", "expired"),
    )
    view = request_commands.add_parser("view")
    view.add_argument("request_id")
    approve = request_commands.add_parser("approve")
    approve.add_argument("request_id")
    approve.add_argument("--reason")
    reject = request_commands.add_parser("reject")
    reject.add_argument("request_id")
    reject.add_argument("--reason")
    evaluate = request_commands.add_parser("evaluate")
    evaluate.add_argument("request_id")

    rules = resources.add_parser("rules")
    rule_commands = rules.add_subparsers(dest="rules_command", required=True)
    create = rule_commands.add_parser("create")
    create.add_argument("--name", required=True)
    create.add_argument("--target-agent-id", required=True)
    create.add_argument("--scope", action="append", dest="scopes", required=True)
    create.add_argument("--max-ttl", required=True)
    rule_commands.add_parser("list")
    disable = rule_commands.add_parser("disable")
    disable.add_argument("rule_id")

    bounds = resources.add_parser("bounds")
    bounds_commands = bounds.add_subparsers(dest="bounds_command", required=True)
    set_bounds = bounds_commands.add_parser("set")
    set_bounds.add_argument("target_agent_id", nargs="?")
    set_bounds.add_argument("--scope", action="append", dest="scopes", required=True)
    show_bounds = bounds_commands.add_parser("show")
    show_bounds.add_argument("target_agent_id", nargs="?")

    audit = resources.add_parser("audit")
    audit_commands = audit.add_subparsers(dest="audit_command", required=True)
    audit_list = audit_commands.add_parser("list")
    audit_list.add_argument("--limit", type=int, default=20)
    audit_list.add_argument("--event")
    audit_list.add_argument("--grant-ref")
    audit_list.add_argument("--boundary-id")
    audit_list.add_argument("--request-id")

    policy = resources.add_parser("policy")
    policy_commands = policy.add_subparsers(dest="policy_command", required=True)
    policy_apply = policy_commands.add_parser("apply")
    policy_apply.add_argument("--file", required=True, type=Path)
    policy_export = policy_commands.add_parser("export")
    policy_export.add_argument("--file", required=True, type=Path)

    storage = resources.add_parser("storage")
    storage_commands = storage.add_subparsers(dest="storage_command", required=True)
    storage_commands.add_parser("info")


def _add_demo_commands(roles: argparse._SubParsersAction) -> None:
    parser = roles.add_parser("demo", help="Run local demonstration checks.")
    commands = parser.add_subparsers(dest="demo_command", required=True)
    commands.add_parser("check")


def _dispatch(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.role == "local":
        _local(args, stdout=stdout)
        return
    if args.role == "agent":
        _agent(args, stdout=stdout)
        return
    if args.role == "operator":
        _operator(args, stdout=stdout)
        return
    if args.role == "demo":
        _demo(args, stdout=stdout)
        return
    raise CliError(f"unknown role: {args.role}")


def _local(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.local_command == "start":
        config = _local_config(args)
        serve_local_service(config)
    if args.local_command == "env":
        body = _local_env_body(args)
        _emit(args, body, _local_env_exports(body), stdout=stdout)
        return
    raise CliError(f"unknown local command: {args.local_command}")


def _agent(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.agent_command == "requests" and args.requests_command == "create":
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/grant-requests",
            headers={"X-Agent-Key": _required(args.agent_key, "agent key")},
            body={
                "scopes": args.scopes,
                "ttl_seconds": _parse_duration_seconds(args.ttl),
                "reason": args.reason,
            },
        )
        _raise_for_status(status, body)
        summary = (
            f"created request {body['request_id']} status={body['status']} "
            f"routing={body.get('routing_hint', '-')} scopes={_scopes(body)}"
        )
        _emit(args, body, summary, stdout=stdout)
        return

    if args.agent_command == "requests" and args.requests_command == "status":
        status, body = _request_json(
            args.endpoint,
            "GET",
            f"/v1/grant-requests/{args.request_id}",
            headers={"X-Agent-Key": _required(args.agent_key, "agent key")},
        )
        _raise_for_status(status, body)
        grant_ref = body.get("issued_grant_ref") or "-"
        summary = (
            f"request {body['request_id']} status={body['status']} "
            f"grant_ref={grant_ref} scopes={_scopes(body)}"
        )
        _emit(args, body, summary, stdout=stdout)
        return

    if args.agent_command == "enforce":
        grant_ref = args.enforce_grant_ref or args.grant_ref or os.environ.get("VINCTOR_GRANT_REF")
        headers = {"X-Agent-Key": _required(args.agent_key, "agent key")}
        if args.boundary_id:
            headers["X-Vinctor-Boundary-Id"] = args.boundary_id
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/enforce",
            headers=headers,
            body={
                "grant_ref": _required(grant_ref, "grant ref"),
                "action": args.action,
                "resource": args.resource,
            },
        )
        if status == 403:
            _emit(args, body, f"deny action={args.action} resource={args.resource}", stdout=stdout)
            raise CliError(str(body.get("reason") or "action_denied"), code=EXIT_DENIED)
        _raise_for_status(status, body)
        summary = (
            f"{body['decision']} action={args.action} resource={args.resource} "
            f"audit_event_id={body.get('audit_event_id')}"
        )
        _emit(args, body, summary, stdout=stdout)
        return

    raise CliError("unknown agent command")


def _operator(args: argparse.Namespace, *, stdout: TextIO) -> None:
    resource = args.operator_resource
    if resource == "requests":
        _operator_requests(args, stdout=stdout)
        return
    if resource == "rules":
        _operator_rules(args, stdout=stdout)
        return
    if resource == "bounds":
        _operator_bounds(args, stdout=stdout)
        return
    if resource == "audit":
        _operator_audit(args, stdout=stdout)
        return
    if resource == "policy":
        _operator_policy(args, stdout=stdout)
        return
    if resource == "storage":
        _operator_storage(args, stdout=stdout)
        return
    raise CliError(f"unknown operator resource: {resource}")


def _operator_requests(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.requests_command
    if command == "list":
        status, body = _request_json(
            args.endpoint,
            "GET",
            "/v1/grant-requests",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        requests = body["grant_requests"]
        if args.status is not None and isinstance(requests, list):
            requests = [
                request
                for request in requests
                if isinstance(request, dict) and request.get("status") == args.status
            ]
            body = {"grant_requests": requests}
        _emit(args, body, _request_list_text(requests), stdout=stdout)
        return
    if command == "view":
        status, body = _request_json(
            args.endpoint,
            "GET",
            f"/v1/grant-requests/{args.request_id}",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(args, body, _request_text(body), stdout=stdout)
        return
    if command in {"approve", "reject"}:
        payload = {"decision_reason": args.reason} if args.reason is not None else None
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grant-requests/{args.request_id}/{command}",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
            body=payload,
        )
        _raise_for_status(status, body)
        grant = body.get("grant")
        grant_ref = (
            grant.get("grant_ref")
            if isinstance(grant, dict)
            else body.get("issued_grant_ref")
        )
        verb = "approved" if command == "approve" else "rejected"
        _emit(
            args,
            body,
            f"{verb} request {body['request_id']} status={body['status']} "
            f"grant_ref={grant_ref or '-'}",
            stdout=stdout,
        )
        return
    if command == "evaluate":
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/grant-requests/{args.request_id}/auto-approve",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        auto = body.get("auto_approval")
        if isinstance(auto, dict) and auto.get("decision") == "approved":
            summary = (
                f"approved request {body['request_id']} grant_ref={body['issued_grant_ref']} "
                f"rule={auto.get('rule_id')}"
            )
        else:
            reason = auto.get("reason") if isinstance(auto, dict) else "-"
            summary = (
                f"pending request {body['request_id']} "
                f"routing=manual_review_required reason={reason}"
            )
        _emit(args, body, summary, stdout=stdout)
        return
    raise CliError(f"unknown requests command: {command}")


def _operator_rules(args: argparse.Namespace, *, stdout: TextIO) -> None:
    command = args.rules_command
    if command == "create":
        status, body = _request_json(
            args.endpoint,
            "POST",
            "/v1/auto-approval-rules",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
            body={
                "name": args.name,
                "target_agent_id": args.target_agent_id,
                "allowed_scopes": args.scopes,
                "max_ttl_seconds": _parse_duration_seconds(args.max_ttl),
            },
        )
        _raise_for_status(status, body)
        _emit(
            args,
            body,
            f"created rule {body['rule_id']} status={body['status']} "
            f"scopes={_scopes(body, 'allowed_scopes')}",
            stdout=stdout,
        )
        return
    if command == "list":
        status, body = _request_json(
            args.endpoint,
            "GET",
            "/v1/auto-approval-rules",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(args, body, _rule_list_text(body["auto_approval_rules"]), stdout=stdout)
        return
    if command == "disable":
        status, body = _request_json(
            args.endpoint,
            "POST",
            f"/v1/auto-approval-rules/{args.rule_id}/disable",
            headers={"X-Workspace-Key": _required(args.workspace_key, "workspace key")},
        )
        _raise_for_status(status, body)
        _emit(args, body, f"disabled rule {body['rule_id']} status={body['status']}", stdout=stdout)
        return
    raise CliError(f"unknown rules command: {command}")


def _operator_bounds(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    agent_id = args.target_agent_id or args.agent_id
    if args.bounds_command == "set":
        service.set_agent_issuable_scope_bounds(
            workspace_id=args.workspace_id,
            agent_id=agent_id,
            scopes=tuple(args.scopes),
            now=datetime.now(UTC),
        )
        body = {"workspace_id": args.workspace_id, "agent_id": agent_id, "scopes": args.scopes}
        _emit(
            args,
            body,
            f"set bounds workspace={args.workspace_id} agent={agent_id} "
            f"scopes={','.join(args.scopes)}",
            stdout=stdout,
        )
        return
    if args.bounds_command == "show":
        scopes = service.scope_bounds_repository.get_bounds(
            workspace_id=args.workspace_id,
            agent_id=agent_id,
        )
        body = {
            "workspace_id": args.workspace_id,
            "agent_id": agent_id,
            "scopes": list(scopes or ()),
        }
        text = (
            f"bounds workspace={args.workspace_id} agent={agent_id} scopes={','.join(scopes)}"
            if scopes
            else f"no bounds workspace={args.workspace_id} agent={agent_id}"
        )
        _emit(args, body, text, stdout=stdout)
        return
    raise CliError(f"unknown bounds command: {args.bounds_command}")


def _operator_audit(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.limit <= 0:
        raise CliError("audit --limit must be positive")
    events = [
        event
        for event in _sqlite_service(args.db).audit_events
        if _audit_event_matches(event, args)
    ][-args.limit :]
    body = {"audit_events": [_audit_body(event) for event in events]}
    _emit(args, body, _audit_list_text(events), stdout=stdout)


def _operator_policy(args: argparse.Namespace, *, stdout: TextIO) -> None:
    service = _sqlite_service(args.db)
    if args.policy_command == "apply":
        try:
            result = apply_policy_file(
                args.file,
                service=service,
                workspace_id=args.workspace_id,
                applied_by=f"workspace:{args.workspace_id}",
                now=datetime.now(UTC),
            )
        except ValueError as error:
            raise CliError(str(error)) from error
        body = asdict(result)
        summary = (
            f"applied policy workspace={result.workspace_id} bounds={result.bounds_set} "
            f"rules_created={result.rules_created} rules_updated={result.rules_updated}"
        )
        _emit(args, body, summary, stdout=stdout)
        return
    if args.policy_command == "export":
        document = export_policy_document(service=service, workspace_id=args.workspace_id)
        try:
            write_policy_file(args.file, document)
        except OSError as error:
            raise CliError(f"could not write policy file: {args.file}") from error
        body = {
            "workspace_id": args.workspace_id,
            "file": str(args.file),
            "agent_bounds": len(document["agent_bounds"]),
            "auto_approval_rules": len(document["auto_approval_rules"]),
        }
        summary = (
            f"exported policy workspace={args.workspace_id} file={args.file} "
            f"bounds={body['agent_bounds']} rules={body['auto_approval_rules']}"
        )
        _emit(args, body, summary, stdout=stdout)
        return
    raise CliError(f"unknown policy command: {args.policy_command}")


def _operator_storage(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.storage_command != "info":
        raise CliError(f"unknown storage command: {args.storage_command}")
    service = _sqlite_service(args.db)
    body = {
        "db_path": str(_required(args.db, "db")),
        "schema_versions": list(service.schema_versions()),
    }
    versions = ",".join(map(str, body["schema_versions"]))
    _emit(args, body, f"storage db={body['db_path']} schema_versions={versions}", stdout=stdout)


def _demo(args: argparse.Namespace, *, stdout: TextIO) -> None:
    if args.demo_command != "check":
        raise CliError(f"unknown demo command: {args.demo_command}")
    with TemporaryDirectory() as temp_dir:
        handle = prepare_local_service(
            LocalLaunchConfig(
                db_path=Path(temp_dir) / "vinctor.sqlite",
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_runner",
                workspace_key="wsk_demo",
                agent_key="aak_demo",
                grant_ref="grt_bootstrap",
                scopes=("execute:ci/test",),
                boundary_name="claude-code-local",
            ),
            now=datetime.now(UTC),
        )
        thread = Thread(target=handle.server.serve_forever, daemon=True)
        thread.start()
        try:
            common = argparse.Namespace(
                endpoint=handle.endpoint,
                workspace_key=handle.workspace_key,
                agent_key=handle.agent_key,
                grant_ref=handle.grant_ref,
                boundary_id=handle.boundary.boundary_id if handle.boundary else None,
                json=args.json,
                output=args.output,
            )
            _request_json(
                common.endpoint,
                "POST",
                "/v1/auto-approval-rules",
                headers={"X-Workspace-Key": common.workspace_key},
                body={
                    "name": "CI auto approval",
                    "target_agent_id": "agent_runner",
                    "allowed_scopes": ["execute:ci/test"],
                    "max_ttl_seconds": 1800,
                },
            )
            _, created = _request_json(
                common.endpoint,
                "POST",
                "/v1/grant-requests",
                headers={"X-Agent-Key": common.agent_key},
                body={
                    "scopes": ["execute:ci/test"],
                    "ttl_seconds": 900,
                    "reason": "demo check",
                },
            )
            _, approved = _request_json(
                common.endpoint,
                "POST",
                f"/v1/grant-requests/{created['request_id']}/auto-approve",
                headers={"X-Workspace-Key": common.workspace_key},
            )
            _, enforced = _request_json(
                common.endpoint,
                "POST",
                "/v1/enforce",
                headers={
                    "X-Agent-Key": common.agent_key,
                    "X-Vinctor-Boundary-Id": common.boundary_id or "",
                },
                body={
                    "grant_ref": approved["issued_grant_ref"],
                    "action": "execute",
                    "resource": "ci/test",
                },
            )
            body = {
                "ok": True,
                "endpoint": handle.endpoint,
                "request_id": created["request_id"],
                "grant_ref": approved["issued_grant_ref"],
                "decision": enforced["decision"],
                "audit_event_count": len(handle.service.audit_events),
            }
            _emit(args, body, "demo check passed", stdout=stdout)
        finally:
            handle.server.shutdown()
            thread.join(timeout=5)
            handle.close()


def _local_config(args: argparse.Namespace) -> LocalLaunchConfig:
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


def _request_json(
    endpoint: str | None,
    method: str,
    path: str,
    *,
    headers: dict[str, str],
    body: object | None = None,
) -> tuple[int, dict[str, object]]:
    endpoint_value = _required(endpoint, "endpoint")
    parsed = urlsplit(endpoint_value)
    if parsed.scheme != "http" or parsed.hostname is None or parsed.port is None:
        raise CliError("endpoint must look like http://127.0.0.1:8765")

    request_headers = {"Content-Type": "application/json", **headers}
    conn = HTTPConnection(parsed.hostname, parsed.port, timeout=5)
    try:
        conn.request(
            method,
            path,
            body=None if body is None else json.dumps(body),
            headers=request_headers,
        )
        response = conn.getresponse()
        raw = response.read()
    except OSError as error:
        raise CliError(f"service unavailable: {error}", code=EXIT_SERVICE) from error
    finally:
        conn.close()
    try:
        parsed_body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CliError("service returned non-JSON response", code=EXIT_SERVICE) from error
    if not isinstance(parsed_body, dict):
        raise CliError("service returned non-object JSON response", code=EXIT_SERVICE)
    return response.status, parsed_body


def _raise_for_status(status: int, body: dict[str, object]) -> None:
    if 200 <= status < 300:
        return
    error = str(body.get("error") or "error")
    reason = str(body.get("reason") or error)
    if status == 401:
        raise CliError(f"{status} {error}: {reason}", code=EXIT_AUTH)
    if status == 403:
        raise CliError(f"{status} {error}: {reason}", code=EXIT_DENIED)
    if status >= 500:
        raise CliError(f"{status} {error}: {reason}", code=EXIT_SERVICE)
    raise CliError(f"{status} {error}: {reason}")


def _sqlite_service(db_path: Path | None) -> SQLiteV1Service:
    path = _required(db_path, "db")
    conn = sqlite3.connect(path)
    return SQLiteV1Service(conn)


def _required(value: object | None, name: str) -> str:
    if value is None or value == "":
        raise CliError(f"{name} is required")
    return str(value)


def _parse_duration_seconds(raw: str) -> int:
    if raw.isdigit():
        value = int(raw)
    else:
        suffix = raw[-1]
        number = raw[:-1]
        if not number.isdigit() or suffix not in {"s", "m", "h"}:
            raise CliError(f"invalid duration: {raw}")
        multiplier = {"s": 1, "m": 60, "h": 3600}[suffix]
        value = int(number) * multiplier
    if value <= 0:
        raise CliError("duration must be positive")
    return value


def _emit(
    args: argparse.Namespace,
    body: dict[str, object],
    text: str,
    *,
    stdout: TextIO,
) -> None:
    if args.json or args.output == "json":
        print(json.dumps(body, sort_keys=True), file=stdout)
    else:
        print(text, file=stdout)


def _emit_error(args: argparse.Namespace, error: CliError, *, stderr: TextIO) -> None:
    if getattr(args, "json", False) or getattr(args, "output", None) == "json":
        print(json.dumps({"ok": False, "error": str(error), "exit_code": error.code}), file=stderr)
    else:
        print(f"error: {error}", file=stderr)


def _scopes(body: dict[str, object], key: str = "requested_scopes") -> str:
    value = body.get(key, [])
    if not isinstance(value, list):
        return "-"
    return ",".join(str(scope) for scope in value)


def _request_text(body: dict[str, object]) -> str:
    routing = body.get("routing_hint") or "-"
    queue_reason = body.get("queue_reason") or body.get("routing_reason") or "-"
    return (
        f"{body['request_id']} status={body['status']} requester={body['requester_agent_id']} "
        f"target={body['target_agent_id']} ttl={body['requested_ttl_seconds']} "
        f"scopes={_scopes(body)} issued={body.get('issued_grant_ref') or '-'} "
        f"routing={routing} queue_reason={queue_reason} reason={body['reason']}"
    )


def _request_list_text(requests: object) -> str:
    if not isinstance(requests, list) or not requests:
        return "no grant requests"
    return "\n".join(_request_text(request) for request in requests if isinstance(request, dict))


def _rule_list_text(rules: object) -> str:
    if not isinstance(rules, list) or not rules:
        return "no auto-approval rules"
    lines = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        lines.append(
            f"{rule['rule_id']} status={rule['status']} target={rule['target_agent_id']} "
            f"max_ttl={rule['max_ttl_seconds']} scopes={_scopes(rule, 'allowed_scopes')} "
            f"name={rule['name']}"
        )
    return "\n".join(lines)


def _audit_event_matches(event: object, args: argparse.Namespace) -> bool:
    if args.event and event.event_type != args.event:
        return False
    if args.grant_ref and event.grant_ref != args.grant_ref:
        return False
    if args.boundary_id and event.boundary_id != args.boundary_id:
        return False
    if args.request_id:
        request_resource = f"grant_request/{args.request_id}"
        if args.request_id not in {event.grant_id, event.grant_ref} and (
            event.resource != request_resource
        ):
            return False
    return True


def _audit_body(event: object) -> dict[str, object]:
    body = asdict(event)
    created_at = body.get("created_at")
    if isinstance(created_at, datetime):
        body["created_at"] = created_at.isoformat()
    return body


def _audit_list_text(events: list[object]) -> str:
    if not events:
        return "no audit events"
    lines = []
    for event in events:
        lines.append(
            f"{event.created_at.isoformat()} {event.event_type} "
            f"decision={event.decision} reason={event.reason} "
            f"agent={event.agent_id} grant_ref={event.grant_ref} "
            f"action={event.action} resource={event.resource} "
            f"scope={event.scope_matched or '-'} boundary={event.boundary_id or '-'}"
        )
    return "\n".join(lines)


def _local_handle_body(handle: object) -> dict[str, object]:
    boundary = getattr(handle, "boundary", None)
    grant = getattr(handle, "grant", None)
    return {
        "endpoint": handle.endpoint,
        "workspace_key": handle.workspace_key,
        "agent_key": handle.agent_key,
        "grant_ref": grant.grant_ref if isinstance(grant, Grant) else None,
        "boundary_id": boundary.boundary_id if boundary is not None else None,
        "db_path": str(handle.db_path),
    }


def _local_env_body(args: argparse.Namespace) -> dict[str, object]:
    return {
        "endpoint": _required(args.endpoint, "endpoint"),
        "workspace_key": _required(args.workspace_key, "workspace key"),
        "agent_key": _required(args.agent_key, "agent key"),
        "grant_ref": _required(args.grant_ref, "grant ref"),
        "boundary_id": args.boundary_id,
    }


def _local_env_exports(body: dict[str, object]) -> str:
    lines = [
        f'export VINCTOR_ENDPOINT="{body["endpoint"]}"',
        f'export VINCTOR_AGENT_KEY="{body["agent_key"]}"',
        f'export VINCTOR_GRANT_REF="{body["grant_ref"]}"',
        f'export VINCTOR_WORKSPACE_KEY="{body["workspace_key"]}"',
    ]
    if body.get("boundary_id"):
        lines.append(f'export VINCTOR_BOUNDARY_ID="{body["boundary_id"]}"')
    return "\n".join(lines)


if __name__ == "__main__":
    main()
