from __future__ import annotations

import argparse
import json
import ssl
import sys
from typing import Any, NamedTuple, TextIO
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen


class SmokeError(Exception):
    pass


class SmokeConfig(NamedTuple):
    endpoint: str
    agent_key: str
    workspace_key: str
    grant_ref: str
    permit_action: str
    permit_resource: str
    deny_action: str
    deny_resource: str
    boundary_id: str | None = None
    timeout_seconds: float = 10.0
    insecure_tls: bool = False


def run_smoke(config: SmokeConfig) -> dict[str, object]:
    health_status, health = _request_json(config, "GET", "/healthz")
    if health_status != 200 or health.get("status") != "ok":
        raise SmokeError(f"health check failed status={health_status}")

    permit_status, permit = _request_json(
        config,
        "POST",
        "/v1/enforce",
        headers=_agent_headers(config),
        body={
            "grant_ref": config.grant_ref,
            "action": config.permit_action,
            "resource": config.permit_resource,
        },
    )
    if permit_status != 200 or permit.get("decision") != "permit":
        raise SmokeError(f"permit enforce failed status={permit_status} body={permit}")

    deny_status, deny = _request_json(
        config,
        "POST",
        "/v1/enforce",
        headers=_agent_headers(config),
        body={
            "grant_ref": config.grant_ref,
            "action": config.deny_action,
            "resource": config.deny_resource,
        },
    )
    if deny_status != 403 or deny.get("decision") != "deny":
        raise SmokeError(f"deny enforce failed status={deny_status} body={deny}")

    query = urlencode({"grant_ref": config.grant_ref, "limit": "20"})
    audit_status, audit = _request_json(
        config,
        "GET",
        f"/v1/audit-events?{query}",
        headers={"X-Workspace-Key": config.workspace_key},
    )
    if audit_status != 200:
        raise SmokeError(f"audit lookup failed status={audit_status} body={audit}")
    events = audit.get("audit_events")
    if not isinstance(events, list):
        raise SmokeError("audit lookup did not return audit_events")

    permit_event_id = _string_or_none(permit.get("audit_event_id"))
    deny_event_id = _string_or_none(deny.get("audit_event_id"))
    event_ids = {
        event.get("event_id")
        for event in events
        if isinstance(event, dict) and isinstance(event.get("event_id"), str)
    }
    if permit_event_id not in event_ids or deny_event_id not in event_ids:
        raise SmokeError("audit lookup did not include both enforce events")

    return {
        "endpoint": config.endpoint,
        "health_status": health["status"],
        "permit_decision": permit["decision"],
        "deny_decision": deny["decision"],
        "audit_event_count": len(events),
        "permit_audit_event_id": permit_event_id,
        "deny_audit_event_id": deny_event_id,
    }


def main(argv: list[str] | None = None, *, stdout: TextIO = sys.stdout) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    config = SmokeConfig(
        endpoint=args.endpoint,
        agent_key=args.agent_key,
        workspace_key=args.workspace_key,
        grant_ref=args.grant_ref,
        permit_action=args.permit_action,
        permit_resource=args.permit_resource,
        deny_action=args.deny_action,
        deny_resource=args.deny_resource,
        boundary_id=args.boundary_id,
        timeout_seconds=args.timeout,
        insecure_tls=args.insecure_tls,
    )
    try:
        result = run_smoke(config)
    except SmokeError as error:
        print(f"preview smoke failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True), file=stdout)
    print("ALL SINGLE-NODE PREVIEW SMOKE STEPS PASSED", file=stdout)
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a single-node preview Vinctor service smoke check.",
    )
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--agent-key", required=True)
    parser.add_argument("--workspace-key", required=True)
    parser.add_argument("--grant-ref", required=True)
    parser.add_argument("--permit-action", default="write")
    parser.add_argument("--permit-resource", default="repo/preview/README.md")
    parser.add_argument("--deny-action", default="write")
    parser.add_argument("--deny-resource", default="repo/other/README.md")
    parser.add_argument("--boundary-id")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--insecure-tls",
        action="store_true",
        help="Skip TLS certificate verification for localhost/internal CA previews.",
    )
    return parser


def _request_json(
    config: SmokeConfig,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: object | None = None,
) -> tuple[int, dict[str, Any]]:
    url = urljoin(config.endpoint.rstrip("/") + "/", path.lstrip("/"))
    payload = None if body is None else json.dumps(body).encode("utf-8")
    request = Request(
        url,
        data=payload,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    context = _ssl_context(config)
    try:
        with urlopen(request, timeout=config.timeout_seconds, context=context) as response:
            return response.status, _decode_json(response.read())
    except HTTPError as error:
        return error.code, _decode_json(error.read())
    except URLError as error:
        raise SmokeError(f"request failed for {method} {path}: {error.reason}") from error


def _ssl_context(config: SmokeConfig) -> ssl.SSLContext | None:
    if not config.endpoint.startswith("https://") or not config.insecure_tls:
        return None
    return ssl._create_unverified_context()


def _agent_headers(config: SmokeConfig) -> dict[str, str]:
    headers = {"X-Agent-Key": config.agent_key}
    if config.boundary_id is not None:
        headers["X-Vinctor-Boundary-Id"] = config.boundary_id
    return headers


def _decode_json(raw: bytes) -> dict[str, Any]:
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as error:
        raise SmokeError("response was not JSON") from error
    if not isinstance(decoded, dict):
        raise SmokeError("response JSON was not an object")
    return decoded


def _string_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


if __name__ == "__main__":
    raise SystemExit(main())
