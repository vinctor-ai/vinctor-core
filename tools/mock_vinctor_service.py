#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, NoReturn, TextIO

MOCK_AGENT_KEY = "aak_mock"
MOCK_GRANT_REF = "grt_mock"


@dataclass(frozen=True)
class MockDecisionConfig:
    default_decision: str = "permit"
    permit: frozenset[str] = frozenset()
    deny: frozenset[str] = frozenset()
    mode: str = "normal"
    status: int = 503
    agent_key: str = MOCK_AGENT_KEY
    grant_ref: str = MOCK_GRANT_REF


@dataclass(frozen=True)
class MockRequestLogEntry:
    action_resource: str | None
    decision: str | None
    status_code: int
    boundary_id: str | None = None


class MockVinctorServer(ThreadingHTTPServer):
    config: MockDecisionConfig
    mock_log: list[MockRequestLogEntry]


def create_mock_server(
    address: tuple[str, int],
    *,
    config: MockDecisionConfig | None = None,
) -> MockVinctorServer:
    server = MockVinctorServer(address, _handler())
    server.config = config or MockDecisionConfig()
    server.mock_log = []
    return server


def load_mock_config(path: Path) -> MockDecisionConfig:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise ValueError(f"could not read mock config: {path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"invalid mock config JSON: {error}") from error
    if not isinstance(data, dict):
        raise ValueError("mock config must be a JSON object")
    return config_from_mapping(data)


def config_from_mapping(data: dict[str, object]) -> MockDecisionConfig:
    extra = sorted(
        set(data)
        - {"default_decision", "permit", "deny", "mode", "status", "agent_key", "grant_ref"}
    )
    if extra:
        raise ValueError(f"unexpected mock config field: {extra[0]}")

    default_decision = _decision_value(data.get("default_decision", "permit"))
    mode = data.get("mode", "normal")
    if mode not in {"normal", "unavailable"}:
        raise ValueError("mode must be normal or unavailable")

    status = data.get("status", 503)
    if not isinstance(status, int) or isinstance(status, bool) or status < 400:
        raise ValueError("status must be an integer HTTP error status")

    agent_key = data.get("agent_key", MOCK_AGENT_KEY)
    if not isinstance(agent_key, str) or agent_key == "":
        raise ValueError("agent_key must be a non-empty string")

    grant_ref = data.get("grant_ref", MOCK_GRANT_REF)
    if not isinstance(grant_ref, str) or grant_ref == "":
        raise ValueError("grant_ref must be a non-empty string")

    return MockDecisionConfig(
        default_decision=default_decision,
        permit=frozenset(_action_resources(data.get("permit", []), field_name="permit")),
        deny=frozenset(_action_resources(data.get("deny", []), field_name="deny")),
        mode=mode,
        status=status,
        agent_key=agent_key,
        grant_ref=grant_ref,
    )


def merge_cli_config(
    base: MockDecisionConfig,
    *,
    default_decision: str | None = None,
    permit: list[str] | None = None,
    deny: list[str] | None = None,
    fail_all: bool = False,
    status: int | None = None,
) -> MockDecisionConfig:
    mode = "unavailable" if fail_all or status is not None else base.mode
    failure_status = status if status is not None else base.status
    permit_values = _action_resources(permit or [], field_name="permit")
    deny_values = _action_resources(deny or [], field_name="deny")
    return MockDecisionConfig(
        default_decision=default_decision or base.default_decision,
        permit=frozenset((*base.permit, *tuple(permit_values))),
        deny=frozenset((*base.deny, *tuple(deny_values))),
        mode=mode,
        status=failure_status,
        agent_key=base.agent_key,
        grant_ref=base.grant_ref,
    )


def run_mock_service(
    argv: list[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        config = _config_from_args(args)
        server = create_mock_server((args.host, args.port), config=config)
    except ValueError as error:
        print(f"error: {error}", file=stderr)
        return 2

    print(_startup_text(server), file=stdout, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> NoReturn:
    raise SystemExit(run_mock_service(argv))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a deterministic mock Vinctor /v1/enforce service.",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--default-decision", choices=("permit", "deny"))
    parser.add_argument("--permit", action="append", default=[])
    parser.add_argument("--deny", action="append", default=[])
    parser.add_argument("--fail-all", action="store_true")
    parser.add_argument("--status", type=int)
    return parser


def _config_from_args(args: argparse.Namespace) -> MockDecisionConfig:
    config = load_mock_config(args.config) if args.config is not None else MockDecisionConfig()
    return merge_cli_config(
        config,
        default_decision=args.default_decision,
        permit=args.permit,
        deny=args.deny,
        fail_all=args.fail_all,
        status=args.status,
    )


def _handler() -> type[BaseHTTPRequestHandler]:
    class MockVinctorHandler(BaseHTTPRequestHandler):
        server: MockVinctorServer
        server_version = "MockVinctor/0.1"

        def do_POST(self) -> None:
            if self.path != "/v1/enforce":
                self._send_json(404, {"error": "not_found", "reason": "route not found"})
                return
            if self.server.config.mode == "unavailable":
                self.server.mock_log.append(
                    MockRequestLogEntry(
                        action_resource=None,
                        decision=None,
                        status_code=self.server.config.status,
                        boundary_id=_header(self.headers, "X-Vinctor-Boundary-Id"),
                    )
                )
                self._send_json(
                    self.server.config.status,
                    {
                        "error": "service_unavailable",
                        "reason": "mock service unavailable",
                    },
                )
                return

            if _header(self.headers, "X-Agent-Key") != self.server.config.agent_key:
                self._send_json(
                    401,
                    {
                        "error": "authentication_required",
                        "reason": "valid X-Agent-Key header is required",
                    },
                )
                return

            parsed = _read_json_body(self)
            if isinstance(parsed, tuple):
                self._send_json(parsed[0], parsed[1])
                return
            body = _parse_enforce_body(parsed)
            if isinstance(body, tuple):
                self._send_json(body[0], body[1])
                return

            action_resource = f"{body['action']}:{body['resource']}"
            decision = _decision_for(action_resource, self.server.config)
            boundary_id = _header(self.headers, "X-Vinctor-Boundary-Id")
            if decision == "permit":
                self.server.mock_log.append(
                    MockRequestLogEntry(
                        action_resource=action_resource,
                        decision="permit",
                        status_code=200,
                        boundary_id=boundary_id,
                    )
                )
                # D-8: hooks verify a permit from the response body — decision
                # plus a non-empty audit_event_id — not the bare HTTP 200. Emit
                # a per-request mock id so the shared mock stays a valid stand-in.
                self._send_json(
                    200,
                    {
                        "decision": "permit",
                        "audit_event_id": f"evt_mock_{len(self.server.mock_log)}",
                    },
                )
                return

            self.server.mock_log.append(
                MockRequestLogEntry(
                    action_resource=action_resource,
                    decision="deny",
                    status_code=403,
                    boundary_id=boundary_id,
                )
            )
            self._send_json(
                403,
                {
                    "decision": "deny",
                    "error": "action_denied",
                    "reason": "action_denied",
                },
            )

        def do_GET(self) -> None:
            self._send_json(
                405,
                {
                    "error": "method_not_allowed",
                    "reason": "POST is required for /v1/enforce",
                },
            )

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _send_json(self, status_code: int, body: dict[str, object]) -> None:
            payload = json.dumps(body, sort_keys=True).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return MockVinctorHandler


def _read_json_body(handler: BaseHTTPRequestHandler) -> object | tuple[int, dict[str, object]]:
    length_header = handler.headers.get("Content-Length")
    if length_header is None:
        return _error(400, "invalid_request", "request body must be a JSON object")
    try:
        length = int(length_header)
    except ValueError:
        return _error(400, "invalid_request", "Content-Length must be an integer")
    raw = handler.rfile.read(length)
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _error(400, "invalid_json", "request body must be valid JSON")


def _parse_enforce_body(body: object) -> dict[str, str] | tuple[int, dict[str, object]]:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")

    required_fields = {"grant_ref", "action", "resource"}
    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields)
    if missing:
        return _error(400, "invalid_request", f"missing required field: {missing[0]}")
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")

    parsed: dict[str, str] = {}
    for field_name in sorted(required_fields):
        value = body[field_name]
        if not isinstance(value, str) or value == "":
            return _error(400, "invalid_request", f"{field_name} must be a non-empty string")
        parsed[field_name] = value
    return parsed


def _decision_for(action_resource: str, config: MockDecisionConfig) -> str:
    if action_resource in config.deny:
        return "deny"
    if action_resource in config.permit:
        return "permit"
    return config.default_decision


def _header(headers: Any, name: str) -> str | None:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _startup_text(server: MockVinctorServer) -> str:
    host, port = server.server_address
    endpoint = f"http://{host}:{port}"
    return "\n".join(
        [
            "# Mock Vinctor service for integration tests only.",
            f"VINCTOR_ENDPOINT={endpoint}",
            "",
            f'export VINCTOR_ENDPOINT="{endpoint}"',
            f'export VINCTOR_AGENT_KEY="{server.config.agent_key}"',
            f'export VINCTOR_GRANT_REF="{server.config.grant_ref}"',
            "",
            "# This mock implements only POST /v1/enforce.",
        ]
    )


def _decision_value(value: object) -> str:
    if value not in {"permit", "deny"}:
        raise ValueError("default_decision must be permit or deny")
    return str(value)


def _action_resources(value: object, *, field_name: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    if any(not isinstance(item, str) or ":" not in item for item in value):
        raise ValueError(f"{field_name} must contain action:resource strings")
    return value


def _error(status_code: int, error: str, reason: str) -> tuple[int, dict[str, object]]:
    return status_code, {"error": error, "reason": reason}


def run_server_in_thread(server: MockVinctorServer) -> Thread:
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


if __name__ == "__main__":
    main()
