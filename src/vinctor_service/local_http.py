from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import urlsplit

from vinctor_service.audit_http import (
    AuditReadService,
    ServiceOperatorResolver,
    handle_v1_audit_events_http,
    handle_v1_service_auth_failures_http,
)
from vinctor_service.auto_approval_http import (
    AutoApprovalAdminService,
    handle_v1_auto_approval_rules_http,
)
from vinctor_service.boundary_http import (
    BoundaryAdminService,
    WorkspaceIdentity,
    WorkspaceIdentityResolver,
    handle_v1_boundaries_http,
)
from vinctor_service.grant_http import GrantLifecycleService, handle_v1_grants_http
from vinctor_service.grant_request_http import (
    GrantRequestService,
    handle_v1_grant_requests_http,
)
from vinctor_service.metrics import Metrics
from vinctor_service.ratelimit import FixedWindowRateLimiter
from vinctor_service.service_config import (
    DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
    DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS,
)
from vinctor_service.v1_http import (
    AgentIdentity,
    AgentIdentityResolver,
    PepIdentity,
    PepIdentityResolver,
    V1DelegatedEnforceService,
    V1EnforceService,
    V1HttpResponse,
    V1TokenService,
    handle_v1_delegated_enforce_http,
    handle_v1_enforce_http,
    handle_v1_tokens_http,
)

Clock = Callable[[], datetime]

# All legitimate request bodies are tiny JSON payloads. Cap the read so a hostile
# (or merely huge) Content-Length cannot pin a worker thread or exhaust memory
# before authentication. Applied by every body-accepting route.
MAX_BODY_BYTES = 64 * 1024

# Reap idle/slow/blocked connections so a slow-loris or a connection that stalls
# mid-body cannot hold a worker thread indefinitely.
HANDLER_TIMEOUT_SECONDS = 15


def create_v1_http_server(
    address: tuple[str, int],
    *,
    service: V1EnforceService,
    agent_identities: Mapping[str, AgentIdentity],
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    auditor_identities: Mapping[str, WorkspaceIdentity] | None = None,
    service_operator_keys: set[str] | None = None,
    pep_identities: Mapping[str, PepIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    auditor_identity_resolver: WorkspaceIdentityResolver | None = None,
    service_operator_resolver: ServiceOperatorResolver | None = None,
    pep_identity_resolver: PepIdentityResolver | None = None,
    clock: Clock | None = None,
    service_mode: str = "local",
    metrics: Metrics | None = None,
    access_log: bool = False,
) -> ThreadingHTTPServer:
    handler = create_v1_http_handler(
        service=service,
        agent_identities=agent_identities,
        workspace_identities=workspace_identities,
        auditor_identities=auditor_identities,
        service_operator_keys=service_operator_keys,
        pep_identities=pep_identities,
        agent_identity_resolver=agent_identity_resolver,
        workspace_identity_resolver=workspace_identity_resolver,
        auditor_identity_resolver=auditor_identity_resolver,
        service_operator_resolver=service_operator_resolver,
        pep_identity_resolver=pep_identity_resolver,
        clock=clock,
        service_mode=service_mode,
        metrics=metrics,
        access_log=access_log,
    )
    return ThreadingHTTPServer(address, handler)


def create_v1_http_handler(
    *,
    service: V1EnforceService,
    agent_identities: Mapping[str, AgentIdentity],
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    auditor_identities: Mapping[str, WorkspaceIdentity] | None = None,
    service_operator_keys: set[str] | None = None,
    pep_identities: Mapping[str, PepIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    auditor_identity_resolver: WorkspaceIdentityResolver | None = None,
    service_operator_resolver: ServiceOperatorResolver | None = None,
    pep_identity_resolver: PepIdentityResolver | None = None,
    clock: Clock | None = None,
    service_mode: str = "local",
    metrics: Metrics | None = None,
    access_log: bool = False,
) -> type[BaseHTTPRequestHandler]:
    agent_keys = dict(agent_identities)
    workspace_keys = dict(workspace_identities or {})
    auditor_keys = dict(auditor_identities or {})
    service_keys = set(service_operator_keys or set())
    pep_keys = dict(pep_identities or {})
    now = clock or _utc_now

    pop_skew_seconds = _resolve_pop_skew_seconds()

    # One shared, opt-in limiter for all handler threads (captured by the closure
    # like pop_skew_seconds). None when VINCTOR_RATE_LIMIT_PER_MINUTE is unset /
    # non-positive -> no rate-limit code path is taken at all (default off).
    _rate_limit_per_minute = _resolve_rate_limit()
    rate_limiter = (
        FixedWindowRateLimiter(max_requests=_rate_limit_per_minute, window_seconds=60)
        if _rate_limit_per_minute is not None
        else None
    )

    # The single-node prototype shares ONE SQLite connection across all
    # ThreadingHTTPServer worker threads. sqlite3 (even check_same_thread=False)
    # is NOT safe for concurrent cursor/transaction use on one connection: a
    # red-team hammering /v1/enforce with several concurrent clients tripped
    # "another row available" / "no more rows available" and dropped connections
    # with no response. Serialize the DB-touching request handling so a request's
    # cursor is fully consumed before the next thread touches the connection.
    db_access_lock = threading.Lock()

    class V1Handler(BaseHTTPRequestHandler):
        server_version = "VinctorLocalHTTP/0.1"
        # Suppress the default "Python/<x.y.z>" suffix BaseHTTPRequestHandler
        # appends to the Server header — it discloses the exact runtime patch
        # version and is of no value to callers (red-team NOTE, 2026-07-12).
        sys_version = ""
        timeout = HANDLER_TIMEOUT_SECONDS

        def do_POST(self) -> None:
            if not self._check_rate_limit():
                return
            self._dispatch("POST")

        def do_GET(self) -> None:
            if not self._check_rate_limit():
                return
            self._dispatch("GET")

        def _check_rate_limit(self) -> bool:
            """Pre-auth volume gate. Returns True when the request may proceed.

            Fail-OPEN: a None limiter, or any exception from allow(), lets the
            request through — this is an availability tool, never an authz gate,
            so it must not become its own DoS. On a real over-limit it writes a
            429 with a generic body and returns False (no routing, no body read).
            """
            if rate_limiter is None:
                return True
            try:
                ok = rate_limiter.allow(self.client_address[0], time.time())
            except Exception:
                return True
            if ok:
                return True
            _send_rate_limited(self)
            return False

        def do_PUT(self) -> None:
            self._dispatch("PUT")

        def do_PATCH(self) -> None:
            self._dispatch("PATCH")

        def do_DELETE(self) -> None:
            self._dispatch("DELETE")

        def _dispatch(self, method: str) -> None:
            self._vinctor_start = time.monotonic()
            self._vinctor_status = None
            self._vinctor_decision = None
            self._vinctor_error = None
            try:
                # Serialize DB access across worker threads (see db_access_lock).
                with db_access_lock:
                    _handle_request(self, method)
            finally:
                _observe(self, method)

        def log_message(self, format: str, *args: Any) -> None:
            return

    def _handle_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        parsed_path = urlsplit(handler.path)
        path = parsed_path.path
        if path == "/healthz":
            _handle_health_request(handler, method)
            return
        if path == "/metrics":
            _handle_metrics_request(handler, method)
            return
        if path == "/v1/enforce/delegated":
            _handle_delegated_enforce_request(handler, method)
            return
        if path == "/v1/enforce":
            _handle_enforce_request(handler, method)
            return
        if path == "/v1/tokens":
            _handle_tokens_request(handler, method)
            return
        if path == "/v1/boundaries" or path.startswith("/v1/boundaries/"):
            _handle_boundary_request(handler, method, path)
            return
        if path == "/v1/auto-approval-rules" or path.startswith(
            "/v1/auto-approval-rules/"
        ):
            _handle_auto_approval_rule_request(handler, method, path)
            return
        if path == "/v1/grant-requests" or path.startswith("/v1/grant-requests/"):
            _handle_grant_request_request(handler, method, path)
            return
        if path == "/v1/grants" or path.startswith("/v1/grants/"):
            _handle_grant_request(handler, method, path, parsed_path.query)
            return
        if path == "/v1/audit-events" or path.startswith("/v1/audit-events/"):
            _handle_audit_request(handler, method, path, parsed_path.query)
            return
        if path == "/v1/service/audit/auth-failures":
            _handle_service_auth_failures_request(
                handler, method, path, parsed_path.query
            )
            return

        _send_json(
            handler,
            V1HttpResponse(
                status_code=404,
                body={"error": "not_found", "reason": "route not found"},
            ),
        )

    def _handle_health_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        if method != "GET":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "GET is required for /healthz",
                    },
                ),
            )
            return

        _send_json(
            handler,
            V1HttpResponse(
                status_code=200,
                body={
                    "status": "ok",
                    "service": "vinctor-service",
                    "mode": service_mode,
                },
            ),
        )

    def _handle_metrics_request(
        handler: BaseHTTPRequestHandler,
        method: str,
    ) -> None:
        if metrics is None:
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=404,
                    body={"error": "not_found", "reason": "route not found"},
                ),
            )
            return
        if method != "GET":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "GET is required for /metrics",
                    },
                ),
            )
            return
        _send_text(
            handler,
            200,
            metrics.render(),
            content_type="text/plain; version=0.0.4",
        )

    def _observe(handler: BaseHTTPRequestHandler, method: str) -> None:
        if metrics is None and not access_log:
            return
        status = getattr(handler, "_vinctor_status", None)
        if status is None:
            return
        path = _route_label(urlsplit(handler.path).path)
        decision = getattr(handler, "_vinctor_decision", None)
        error = getattr(handler, "_vinctor_error", None)
        if metrics is not None:
            metrics.increment(
                "vinctor_http_requests_total",
                method=method,
                path=path,
                status=str(status),
            )
            if decision in ("permit", "deny"):
                metrics.increment(
                    "vinctor_enforce_decisions_total",
                    decision=decision,
                )
        if access_log:
            start = getattr(handler, "_vinctor_start", None)
            latency_ms = (
                round((time.monotonic() - start) * 1000, 1)
                if start is not None
                else 0.0
            )
            line: dict[str, object] = {
                "ts": now().isoformat(),
                "method": method,
                "path": path,
                "status": status,
                "latency_ms": latency_ms,
            }
            if decision is not None:
                line["decision"] = decision
            if error is not None:
                line["error"] = error
            print(json.dumps(line, sort_keys=True), file=sys.stderr, flush=True)

    def _handle_enforce_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        if method != "POST":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "POST is required for /v1/enforce",
                    },
                ),
            )
            return

        parsed = _read_json_body(handler)
        if isinstance(parsed, V1HttpResponse):
            _send_json(handler, parsed)
            return

        response = handle_v1_enforce_http(
            headers=dict(handler.headers.items()),
            body=parsed,
            agent_identities=agent_keys,
            agent_identity_resolver=agent_identity_resolver,
            service=service,
            now=now(),
        )
        _send_json(handler, response)

    def _handle_delegated_enforce_request(
        handler: BaseHTTPRequestHandler,
        method: str,
    ) -> None:
        if method != "POST":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "POST is required for /v1/enforce/delegated",
                    },
                ),
            )
            return

        parsed = _read_json_body(handler)
        if isinstance(parsed, V1HttpResponse):
            _send_json(handler, parsed)
            return

        response = handle_v1_delegated_enforce_http(
            headers=dict(handler.headers.items()),
            body=parsed,
            pep_identities=pep_keys,
            pep_identity_resolver=pep_identity_resolver,
            service=cast(V1DelegatedEnforceService, service),
            now=now(),
            pop_skew_seconds=pop_skew_seconds,
        )
        _send_json(handler, response)

    def _handle_tokens_request(
        handler: BaseHTTPRequestHandler,
        method: str,
    ) -> None:
        if method != "POST":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "POST is required for /v1/tokens",
                    },
                ),
            )
            return

        parsed = _read_json_body(handler)
        if isinstance(parsed, V1HttpResponse):
            _send_json(handler, parsed)
            return

        response = handle_v1_tokens_http(
            headers=dict(handler.headers.items()),
            body=parsed,
            agent_identities=agent_keys,
            agent_identity_resolver=agent_identity_resolver,
            service=cast(V1TokenService, service),
            now=now(),
            max_ttl=int(
                os.environ.get(
                    "VINCTOR_SUBJECT_TOKEN_MAX_TTL_SECONDS",
                    DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
                )
            ),
        )
        _send_json(handler, response)

    def _handle_boundary_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
    ) -> None:
        body: object = None
        if method == "POST" and path == "/v1/boundaries":
            parsed = _read_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        response = handle_v1_boundaries_http(
            method=method,
            path=path,
            headers=dict(handler.headers.items()),
            body=body,
            workspace_identities=workspace_keys,
            workspace_identity_resolver=workspace_identity_resolver,
            service=cast(BoundaryAdminService, service),
            now=now(),
        )
        _send_json(handler, response)

    def _handle_auto_approval_rule_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
    ) -> None:
        body: object = None
        if method == "POST" and path == "/v1/auto-approval-rules":
            parsed = _read_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        response = handle_v1_auto_approval_rules_http(
            method=method,
            path=path,
            headers=dict(handler.headers.items()),
            body=body,
            workspace_identities=workspace_keys,
            workspace_identity_resolver=workspace_identity_resolver,
            service=cast(AutoApprovalAdminService, service),
            now=now(),
        )
        _send_json(handler, response)

    def _handle_grant_request_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
    ) -> None:
        body: object = None
        if method == "POST":
            parsed = _read_optional_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        response = handle_v1_grant_requests_http(
            method=method,
            path=path,
            headers=dict(handler.headers.items()),
            body=body,
            agent_identities=agent_keys,
            workspace_identities=workspace_keys,
            agent_identity_resolver=agent_identity_resolver,
            workspace_identity_resolver=workspace_identity_resolver,
            service=cast(GrantRequestService, service),
            now=now(),
        )
        _send_json(handler, response)

    def _handle_grant_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
        query_string: str,
    ) -> None:
        body: object = None
        if method == "POST" and path == "/v1/grants":
            parsed = _read_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        response = handle_v1_grants_http(
            method=method,
            path=path,
            headers=dict(handler.headers.items()),
            body=body,
            query_string=query_string,
            workspace_identities=workspace_keys,
            workspace_identity_resolver=workspace_identity_resolver,
            service=cast(GrantLifecycleService, service),
            now=now(),
        )
        _send_json(handler, response)

    def _handle_audit_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
        query_string: str,
    ) -> None:
        response = handle_v1_audit_events_http(
            method=method,
            path=path,
            query_string=query_string,
            headers=dict(handler.headers.items()),
            workspace_identities=workspace_keys,
            workspace_identity_resolver=workspace_identity_resolver,
            auditor_identities=auditor_keys,
            auditor_identity_resolver=auditor_identity_resolver,
            service=cast(AuditReadService, service),
            now=now(),
        )
        _send_json(handler, response)

    def _handle_service_auth_failures_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
        query_string: str,
    ) -> None:
        response = handle_v1_service_auth_failures_http(
            method=method,
            path=path,
            query_string=query_string,
            headers=dict(handler.headers.items()),
            service_operator_keys=service_keys,
            service_operator_resolver=service_operator_resolver,
            service=cast(AuditReadService, service),
            now=now(),
        )
        _send_json(handler, response)

    return V1Handler


_EXACT_ROUTES = frozenset(
    {
        "/healthz",
        "/metrics",
        "/v1/enforce/delegated",
        "/v1/enforce",
        "/v1/tokens",
        "/v1/service/audit/auth-failures",
    }
)

_COLLECTION_ROUTES = (
    "/v1/boundaries",
    "/v1/auto-approval-rules",
    "/v1/grant-requests",
    "/v1/grants",
    "/v1/audit-events",
)


def _route_label(path: str) -> str:
    """Map a request path to a fixed, low-cardinality route template.

    Only server-defined templates are ever returned, never the raw
    client-supplied path. Id segments collapse to ``:id`` and any
    unrecognized path collapses to ``other`` so that user-controlled
    strings (grant refs, ids, junk) can never become a metric label.
    """
    if path in _EXACT_ROUTES:
        return path
    for collection in _COLLECTION_ROUTES:
        if path == collection:
            return collection
        if path.startswith(collection + "/"):
            return collection + "/:id"
    return "other"


def _resolve_pop_skew_seconds() -> int:
    """Parse VINCTOR_SUBJECT_TOKEN_POP_SKEW_SECONDS once at handler construction.

    An invalid value falls back to the documented default rather than raising a
    per-request 500 on the delegated enforce path.
    """
    raw = os.environ.get(
        "VINCTOR_SUBJECT_TOKEN_POP_SKEW_SECONDS",
        DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS,
    )
    try:
        return int(raw)
    except (TypeError, ValueError):
        return int(DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS)


def _resolve_rate_limit() -> int | None:
    """Parse VINCTOR_RATE_LIMIT_PER_MINUTE once at handler construction.

    Returns a positive int (the per-minute, per-source request cap) or None.
    Unset, non-positive, or unparseable -> None (limiter disabled, no behavior
    change). Parsed once here, never per request.
    """
    raw = os.environ.get("VINCTOR_RATE_LIMIT_PER_MINUTE")
    if raw is None:
        return None
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return None
    return value if value > 0 else None


def _read_optional_json_body(handler: BaseHTTPRequestHandler) -> object | V1HttpResponse:
    length_header = handler.headers.get("Content-Length")
    if length_header is None or length_header == "0":
        return None
    return _read_json_body(handler)


def _read_json_body(handler: BaseHTTPRequestHandler) -> object | V1HttpResponse:
    length_header = handler.headers.get("Content-Length")
    try:
        length = int(length_header or "0")
    except ValueError:
        return V1HttpResponse(
            status_code=400,
            body={
                "error": "invalid_request",
                "reason": "Content-Length must be an integer",
            },
        )

    # Bound the read BEFORE touching the socket: reject a negative length (which
    # would make rfile.read(-1) drain the connection) and any length above the
    # cap, with a clean response instead of buffering a hostile body.
    if length < 0:
        return V1HttpResponse(
            status_code=400,
            body={
                "error": "invalid_request",
                "reason": "Content-Length must not be negative",
            },
        )
    if length > MAX_BODY_BYTES:
        return V1HttpResponse(
            status_code=413,
            body={
                "error": "payload_too_large",
                "reason": f"request body must not exceed {MAX_BODY_BYTES} bytes",
            },
        )

    raw_body = handler.rfile.read(min(length, MAX_BODY_BYTES))
    try:
        return json.loads(raw_body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return V1HttpResponse(
            status_code=400,
            body={
                "error": "invalid_json",
                "reason": "request body must be valid JSON",
            },
        )


def _send_json(handler: BaseHTTPRequestHandler, response: V1HttpResponse) -> None:
    handler._vinctor_status = response.status_code  # type: ignore[attr-defined]
    if isinstance(response.body, dict):
        handler._vinctor_decision = response.body.get("decision")  # type: ignore[attr-defined]
        handler._vinctor_error = response.body.get("error")  # type: ignore[attr-defined]
    payload = json.dumps(response.body, sort_keys=True).encode("utf-8")
    handler.send_response(response.status_code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _send_rate_limited(handler: BaseHTTPRequestHandler) -> None:
    """Write the pre-auth 429 with a generic body and nothing else disclosed."""
    handler._vinctor_status = 429  # type: ignore[attr-defined]
    payload = json.dumps({"error": "rate_limited"}, sort_keys=True).encode("utf-8")
    handler.send_response(429)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(payload)))
    handler.send_header("Retry-After", "60")
    handler.end_headers()
    handler.wfile.write(payload)


def _send_text(
    handler: BaseHTTPRequestHandler,
    status: int,
    body: str,
    *,
    content_type: str,
) -> None:
    handler._vinctor_status = status  # type: ignore[attr-defined]
    payload = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def _utc_now() -> datetime:
    return datetime.now(UTC)
