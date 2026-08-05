from __future__ import annotations

import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager, nullcontext
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from math import floor
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
    create_v1_auto_approval_rule_response,
    handle_v1_auto_approval_rules_http,
    parse_v1_auto_approval_rule_create_body,
)
from vinctor_service.boundary_http import (
    BoundaryAdminService,
    WorkspaceIdentity,
    WorkspaceIdentityResolver,
    create_v1_boundary_response,
    handle_v1_boundaries_http,
    parse_v1_boundary_create_body,
)
from vinctor_service.grant_http import (
    GrantLifecycleService,
    handle_v1_grants_http,
    issue_v1_grant_response,
    parse_v1_grant_issue_body,
)
from vinctor_service.grant_request_http import (
    GrantRequestDecisionAction,
    GrantRequestService,
    auto_approve_v1_grant_request_response,
    decide_v1_grant_request_response,
    handle_v1_grant_requests_http,
    parse_v1_grant_request_auto_approve_body,
    parse_v1_grant_request_decision_body,
)
from vinctor_service.health_checks import (
    BoundedBackendProbe,
    HealthCheck,
    health_response,
    readiness_response,
)
from vinctor_service.idempotency_http import (
    AuthenticatedIdempotencyScope,
    HttpIdempotencyRequest,
    IdempotentHttpMutationService,
    cacheable_json_outcome,
    encode_json_response,
    execute_idempotent_http,
)
from vinctor_service.idempotency_models import (
    CacheableTerminalOutcome,
    IdempotencyMutation,
    PreSerializedHttpResponse,
    RequestFingerprintInput,
)
from vinctor_service.metrics import Metrics
from vinctor_service.oidc import OidcTokenVerifier
from vinctor_service.postgres_connection import PostgresConnectionUnavailable
from vinctor_service.ratelimit import (
    FixedWindowRateLimiter,
    IpNetwork,
    parse_trusted_proxy_cidrs,
    resolve_rate_limit_source,
)
from vinctor_service.service_config import (
    DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
    DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS,
)
from vinctor_service.sqlite_pool_admission import SQLitePoolUnavailable
from vinctor_service.v1_http import (
    AgentIdentity,
    AgentIdentityResolver,
    PepIdentity,
    PepIdentityResolver,
    V1DelegatedEnforceService,
    V1EnforceService,
    V1HttpResponse,
    V1ObserveService,
    V1SimulateService,
    V1TokenService,
    handle_v1_delegated_enforce_http,
    handle_v1_enforce_http,
    handle_v1_observe_http,
    handle_v1_simulate_http,
    handle_v1_tokens_http,
    mint_v1_token_http_result,
    parse_v1_token_mint_body,
)

Clock = Callable[[], datetime]
RequestScope = Callable[[], AbstractContextManager[None]]

# Routes that never lease a SQLite request-scope connection. /healthz performs
# no backend work at all on any backend (PKA-117): liveness answers "can this
# process serve", and wiring it to the durable store made a Postgres outage
# restart every pod at once. /readyz does not lease a request-scope connection
# either; its injected bounded readiness check owns any backend work.
DATABASE_FREE_PATHS = frozenset({"/healthz", "/metrics", "/readyz"})


def _needs_database(raw_path: str) -> bool:
    return urlsplit(raw_path).path not in DATABASE_FREE_PATHS


# The liveness path is additionally exempt from the pre-auth volume gate
# (PKA-43 revision). A 429'd /healthz reads as a FAILED liveness probe, and the
# restart it triggers removes capacity under exactly the load the limiter
# exists to survive — the same restart-loop failure mode the request-scope
# exemption above closed (#155). The rate-limit and database-health decisions
# are separate questions, hence separate sets. /readyz and /metrics stay gated
# on purpose: readiness's failure mode is "stop sending me traffic" (correct
# under genuine overload, self-healing, no restart). Keeping it gated also
# preserves the pre-auth volume budget; metrics is operator-facing, not a
# probe, and per-source budgets keep an attacker from spending the scraper's.
# /readyz is unauthenticated and does reach the backend, so the volume gate is
# not its only defence: its check is bounded and single-flight
# (BoundedBackendProbe), which caps a probe flood of any size at one
# outstanding backend query.
# Exemption is GET-only: only the liveness probe itself needs to always
# answer. A non-GET /healthz has no liveness meaning, lands on the health
# route's 405 arm regardless, and must consume budget like any other request —
# otherwise POST/PUT/PATCH/DELETE to /healthz becomes an unauthenticated path
# around the volume gate.
RATE_LIMIT_EXEMPT_PATHS = frozenset({"/healthz"})

# All legitimate request bodies are tiny JSON payloads. Cap the read so a hostile
# (or merely huge) Content-Length cannot pin a worker thread or exhaust memory
# before authentication. Applied by every body-accepting route.
MAX_BODY_BYTES = 64 * 1024

# Reap idle/slow/blocked connections so a slow-loris or a connection that stalls
# mid-body cannot hold a worker thread indefinitely.
HANDLER_TIMEOUT_SECONDS = 15


class _V1HttpServer(ThreadingHTTPServer):
    """Ties the readiness worker's lifetime to the server's.

    Both runtime handles call server_close() before closing the backend
    connection, so stopping the worker here is what keeps it from being
    mid-probe on a connection that is being closed underneath it — and keeps a
    served /readyz from leaking an unjoinable thread that holds the pool or
    connection for the process lifetime.
    """

    readiness_probe: BoundedBackendProbe | None = None

    def server_close(self) -> None:
        probe = self.readiness_probe
        if probe is not None:
            probe.close()
        super().server_close()


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
    readiness_check: HealthCheck | None = None,
    oidc_token_verifier: OidcTokenVerifier | None = None,
    request_scope: RequestScope | None = None,
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
        readiness_check=readiness_check,
        oidc_token_verifier=oidc_token_verifier,
        request_scope=request_scope,
    )
    server = _V1HttpServer(address, handler)
    server.readiness_probe = getattr(handler, "readiness_probe", None)
    return server


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
    readiness_check: HealthCheck | None = None,
    oidc_token_verifier: OidcTokenVerifier | None = None,
    request_scope: RequestScope | None = None,
) -> type[BaseHTTPRequestHandler]:
    agent_keys = dict(agent_identities)
    workspace_keys = dict(workspace_identities or {})
    auditor_keys = dict(auditor_identities or {})
    service_keys = set(service_operator_keys or set())
    pep_keys = dict(pep_identities or {})
    now = clock or _utc_now
    # There is deliberately no liveness_check hook: /healthz must stay a pure
    # process signal (PKA-117). Readiness runs the injected backend check under
    # an explicit deadline so a hung socket cannot hold /readyz open.
    readiness_probe = BoundedBackendProbe(readiness_check) if readiness_check is not None else None
    is_ready: HealthCheck = readiness_probe if readiness_probe is not None else (lambda: True)
    open_request_scope = request_scope or nullcontext

    def resolve_workspace_identity(raw_key: str, used_at: datetime) -> WorkspaceIdentity | None:
        identity = (
            workspace_identity_resolver(raw_key, used_at)
            if workspace_identity_resolver is not None
            else workspace_keys.get(raw_key)
        )
        if identity is not None or oidc_token_verifier is None:
            return identity
        principal = oidc_token_verifier.verify(raw_key)
        if principal is None or principal.workspace_id is None or "operator" not in principal.roles:
            return None
        return WorkspaceIdentity(workspace_id=principal.workspace_id)

    def resolve_auditor_identity(raw_key: str, used_at: datetime) -> WorkspaceIdentity | None:
        identity = (
            auditor_identity_resolver(raw_key, used_at)
            if auditor_identity_resolver is not None
            else auditor_keys.get(raw_key)
        )
        if identity is not None or oidc_token_verifier is None:
            return identity
        principal = oidc_token_verifier.verify(raw_key)
        if (
            principal is None
            or principal.workspace_id is None
            or not principal.roles.intersection({"operator", "auditor"})
        ):
            return None
        return WorkspaceIdentity(workspace_id=principal.workspace_id)

    def resolve_service_operator(raw_key: str, used_at: datetime) -> bool:
        authenticated = (
            service_operator_resolver(raw_key, used_at)
            if service_operator_resolver is not None
            else raw_key in service_keys
        )
        if authenticated or oidc_token_verifier is None:
            return authenticated
        principal = oidc_token_verifier.verify(raw_key)
        return principal is not None and "service_operator" in principal.roles

    def workspace_idempotency_scope(
        headers: Mapping[str, str],
        request_now: datetime,
    ) -> AuthenticatedIdempotencyScope | None:
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        raw_workspace_key = normalized_headers.get("x-workspace-key")
        if raw_workspace_key is None:
            return None
        identity = resolve_workspace_identity(raw_workspace_key, request_now)
        if identity is None:
            return None
        return AuthenticatedIdempotencyScope(
            workspace_id=identity.workspace_id,
            principal=f"workspace:{identity.workspace_id}",
        )

    def agent_idempotency_scope(
        headers: Mapping[str, str],
        request_now: datetime,
    ) -> AuthenticatedIdempotencyScope | None:
        normalized_headers = {key.lower(): value for key, value in headers.items()}
        raw_agent_key = normalized_headers.get("x-agent-key")
        if raw_agent_key is None:
            return None
        identity = (
            agent_identity_resolver(raw_agent_key, request_now)
            if agent_identity_resolver is not None
            else agent_keys.get(raw_agent_key)
        )
        if identity is None:
            return None
        return AuthenticatedIdempotencyScope(
            workspace_id=identity.workspace_id,
            principal=f"agent:{identity.agent_id}",
        )

    pop_skew_seconds = _resolve_pop_skew_seconds()

    # One shared, opt-in limiter for all handler threads (captured by the closure
    # like pop_skew_seconds). None when VINCTOR_RATE_LIMIT_PER_MINUTE is unset /
    # non-positive -> no rate-limit code path is taken at all (default off).
    _rate_limit_per_minute = _resolve_rate_limit()
    trusted_proxies = _resolve_trusted_proxies()
    rate_limiter = (
        FixedWindowRateLimiter(max_requests=_rate_limit_per_minute, window_seconds=60)
        if _rate_limit_per_minute is not None
        else None
    )

    class V1Handler(BaseHTTPRequestHandler):
        server_version = "VinctorLocalHTTP/0.1"
        # Suppress the default "Python/<x.y.z>" suffix BaseHTTPRequestHandler
        # appends to the Server header — it discloses the exact runtime patch
        # version and is of no value to callers (red-team NOTE, 2026-07-12).
        sys_version = ""
        timeout = HANDLER_TIMEOUT_SECONDS

        def do_POST(self) -> None:
            self._dispatch("POST")

        def do_GET(self) -> None:
            self._dispatch("GET")

        def _check_rate_limit(self, method: str) -> bool:
            """Pre-auth volume gate. Returns True when the request may proceed.

            Called once, from _dispatch, so every do_* method is covered without
            opting in — PKA-43 happened because the call sat at the top of
            do_POST/do_GET only and PUT/PATCH/DELETE never opted in.

            The liveness path is exempt and consumes no budget, but only for
            GET: liveness must answer (see RATE_LIMIT_EXEMPT_PATHS). A non-GET
            /healthz has no liveness meaning and is gated like everything else,
            so the exemption can never be bent into an un-gated path to the
            connection pool.

            Fail-OPEN: a None limiter, or any exception from allow(), lets the
            request through — this is an availability tool, never an authz gate,
            so it must not become its own DoS. On a real over-limit it writes a
            429 with a generic body and returns False (no routing, no body read,
            no request-scope lease).
            """
            if rate_limiter is None:
                return True
            try:
                if method == "GET" and urlsplit(self.path).path in RATE_LIMIT_EXEMPT_PATHS:
                    return True
                forwarded_values = self.headers.get_all("X-Forwarded-For")
                forwarded_for = ",".join(forwarded_values) if forwarded_values else None
                source = resolve_rate_limit_source(
                    peer=self.client_address[0],
                    forwarded_for=forwarded_for,
                    trusted_proxies=trusted_proxies,
                )
                ok = rate_limiter.allow(source, time.time())
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
                # Pre-auth volume gate at the single dispatch chokepoint. It
                # runs BEFORE the request scope: an over-limit request must be
                # refused without leasing a pooled connection, or the flood the
                # limiter exists to stop would occupy the pool (PKA-43). It sits
                # INSIDE the try/finally deliberately: a 429 is observed in
                # metrics and the access log like every other pre-auth
                # rejection.
                if not self._check_rate_limit(method):
                    return
                raw_idempotency_headers = self.headers.get_all("Idempotency-Key")
                idempotency_headers = (
                    tuple(raw_idempotency_headers) if raw_idempotency_headers is not None else None
                )
                if _needs_database(self.path):
                    # SQLite runtimes lease one independent connection/service
                    # for the whole request. Other backends use the no-op
                    # default.
                    with open_request_scope():
                        _handle_request(self, method, idempotency_headers)
                else:
                    _handle_request(self, method, idempotency_headers)
            except (SQLitePoolUnavailable, PostgresConnectionUnavailable):
                # Both backends shed load the same way. Without the Postgres
                # arm, a connection failure there escaped the handler entirely
                # and the client got a dropped connection with no response
                # instead of a fail-closed 503 (PKA-232).
                _send_json(
                    self,
                    V1HttpResponse(
                        status_code=503,
                        body={"error": "service_unavailable"},
                    ),
                )
            finally:
                _observe(self, method)

        def log_message(self, format: str, *args: Any) -> None:
            return

    def _handle_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        idempotency_headers: tuple[str, ...] | None,
    ) -> None:
        parsed_path = urlsplit(handler.path)
        path = parsed_path.path
        if path == "/healthz":
            _handle_health_request(handler, method)
            return
        if path == "/readyz":
            _handle_readiness_request(handler, method)
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
        if path == "/v1/observe":
            _handle_observe_request(handler, method)
            return
        if path == "/v1/simulate":
            _handle_simulate_request(handler, method)
            return
        if path == "/v1/tokens":
            _handle_tokens_request(handler, method, idempotency_headers)
            return
        if path == "/v1/boundaries" or path.startswith("/v1/boundaries/"):
            _handle_boundary_request(handler, method, path, idempotency_headers)
            return
        if path == "/v1/auto-approval-rules" or path.startswith("/v1/auto-approval-rules/"):
            _handle_auto_approval_rule_request(handler, method, path, idempotency_headers)
            return
        if path == "/v1/grant-requests" or path.startswith("/v1/grant-requests/"):
            _handle_grant_request_request(handler, method, path, idempotency_headers)
            return
        if path == "/v1/grants" or path.startswith("/v1/grants/"):
            _handle_grant_request(
                handler,
                method,
                path,
                parsed_path.query,
                idempotency_headers,
            )
            return
        if path == "/v1/audit-events" or path.startswith("/v1/audit-events/"):
            _handle_audit_request(handler, method, path, parsed_path.query)
            return
        if path == "/v1/service/audit/auth-failures":
            _handle_service_auth_failures_request(handler, method, path, parsed_path.query)
            return

        _send_json(
            handler,
            V1HttpResponse(
                status_code=404,
                body={"error": "not_found", "reason": "route not found"},
            ),
        )

    def _send_idempotent_mutation(
        handler: BaseHTTPRequestHandler,
        request: HttpIdempotencyRequest,
        mutation: IdempotencyMutation,
    ) -> None:
        idempotent_service = service if isinstance(service, IdempotentHttpMutationService) else None
        _send_pre_serialized(
            handler,
            execute_idempotent_http(idempotent_service, request, mutation),
        )

    def _handle_health_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        _send_json(handler, health_response(method, service_mode))

    def _handle_readiness_request(
        handler: BaseHTTPRequestHandler,
        method: str,
    ) -> None:
        _send_json(handler, readiness_response(method, is_ready))

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
        start = getattr(handler, "_vinctor_start", None)
        latency_seconds = (time.monotonic() - start) if start is not None else 0.0
        if metrics is not None:
            metrics.increment(
                "vinctor_http_requests_total",
                method=method,
                path=path,
                status=str(status),
            )
            # Per-request latency, exported as a route-labelled histogram so SLO
            # monitoring no longer has to parse the JSON access log. Labels stay
            # method/path only (status is not a histogram label) to bound
            # cardinality; path is already collapsed to a fixed route template.
            metrics.observe(
                "vinctor_http_request_duration_seconds",
                latency_seconds,
                method=method,
                path=path,
            )
            # Error responses get their own counter keyed by the disclosed error
            # code, so error-rate alerts don't have to sum every 4xx/5xx status.
            if status >= 400:
                metrics.increment(
                    "vinctor_http_errors_total",
                    method=method,
                    path=path,
                    status=str(status),
                    error=error or "unknown",
                )
            if decision in ("permit", "deny"):
                metrics.increment(
                    "vinctor_enforce_decisions_total",
                    decision=decision,
                )
        if access_log:
            latency_ms = round(latency_seconds * 1000, 1)
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

    def _handle_observe_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        if method != "POST":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "POST is required for /v1/observe",
                    },
                ),
            )
            return

        parsed = _read_json_body(handler)
        if isinstance(parsed, V1HttpResponse):
            _send_json(handler, parsed)
            return

        response = handle_v1_observe_http(
            headers=dict(handler.headers.items()),
            body=parsed,
            agent_identities=agent_keys,
            agent_identity_resolver=agent_identity_resolver,
            service=cast(V1ObserveService, service),
            now=now(),
        )
        _send_json(handler, response)

    def _handle_simulate_request(handler: BaseHTTPRequestHandler, method: str) -> None:
        if method != "POST":
            _send_json(
                handler,
                V1HttpResponse(
                    status_code=405,
                    body={
                        "error": "method_not_allowed",
                        "reason": "POST is required for /v1/simulate",
                    },
                ),
            )
            return

        parsed = _read_json_body(handler)
        if isinstance(parsed, V1HttpResponse):
            _send_json(handler, parsed)
            return

        response = handle_v1_simulate_http(
            headers=dict(handler.headers.items()),
            body=parsed,
            agent_identities=agent_keys,
            agent_identity_resolver=agent_identity_resolver,
            service=cast(V1SimulateService, service),
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
        idempotency_headers: tuple[str, ...] | None,
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

        headers = dict(handler.headers.items())
        request_now = now()
        max_ttl = int(
            os.environ.get(
                "VINCTOR_SUBJECT_TOKEN_MAX_TTL_SECONDS",
                DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
            )
        )

        def mutate() -> V1HttpResponse:
            return handle_v1_tokens_http(
                headers=headers,
                body=parsed,
                agent_identities=agent_keys,
                agent_identity_resolver=agent_identity_resolver,
                service=cast(V1TokenService, service),
                now=request_now,
                max_ttl=max_ttl,
            )

        if idempotency_headers is None:
            _send_json(handler, mutate())
            return
        scope = agent_idempotency_scope(headers, request_now)
        if scope is None:
            _send_json(handler, mutate())
            return
        parsed_request = parse_v1_token_mint_body(parsed, max_ttl=max_ttl)
        if isinstance(parsed_request, V1HttpResponse):
            _send_json(handler, parsed_request)
            return
        identity = AgentIdentity(
            workspace_id=scope.workspace_id,
            agent_id=scope.principal.removeprefix("agent:"),
        )

        def mutation() -> CacheableTerminalOutcome:
            result = mint_v1_token_http_result(
                parsed_request,
                identity=identity,
                service=cast(V1TokenService, service),
                now=request_now,
            )
            replay_not_after_epoch = None
            if result.response.status_code == 201:
                expires_at = result.authoritative_result.expires_at
                assert expires_at is not None
                replay_not_after_epoch = floor(expires_at.timestamp())
            return cacheable_json_outcome(
                result.response,
                replay_not_after_epoch,
            )

        request = HttpIdempotencyRequest(
            fingerprint_input=RequestFingerprintInput(
                method="POST",
                path="/v1/tokens",
                authenticated_workspace_id=scope.workspace_id,
                authenticated_principal=scope.principal,
                operation="subject_token.mint.v1",
                request_body=json.dumps(
                    {
                        "grant_ref": parsed_request.grant_ref,
                        "audience": parsed_request.audience,
                        "ttl_seconds": parsed_request.ttl_seconds,
                        "action": parsed_request.bound_action,
                        "resource": parsed_request.bound_resource,
                        "pop": parsed_request.pop,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            ),
            raw_key_headers=idempotency_headers,
        )
        _send_idempotent_mutation(handler, request, mutation)

    def _handle_boundary_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
        idempotency_headers: tuple[str, ...] | None,
    ) -> None:
        body: object = None
        if method == "POST" and path == "/v1/boundaries":
            parsed = _read_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        headers = _authorization_headers(handler, "X-Workspace-Key")
        request_now = now()

        def mutate() -> V1HttpResponse:
            return handle_v1_boundaries_http(
                method=method,
                path=path,
                headers=headers,
                body=body,
                workspace_identities=workspace_keys,
                workspace_identity_resolver=resolve_workspace_identity,
                service=cast(BoundaryAdminService, service),
                now=request_now,
            )

        if idempotency_headers is None or method != "POST" or path != "/v1/boundaries":
            _send_json(handler, mutate())
            return
        scope = workspace_idempotency_scope(headers, request_now)
        if scope is None:
            _send_json(handler, mutate())
            return
        parsed_request = parse_v1_boundary_create_body(body)
        if isinstance(parsed_request, V1HttpResponse):
            _send_json(handler, parsed_request)
            return
        identity = WorkspaceIdentity(workspace_id=scope.workspace_id)
        request = HttpIdempotencyRequest(
            fingerprint_input=RequestFingerprintInput(
                method="POST",
                path=path,
                authenticated_workspace_id=scope.workspace_id,
                authenticated_principal=scope.principal,
                operation="boundary.create.v1",
                request_body=json.dumps(
                    {
                        "name": parsed_request.name,
                        "runtime": parsed_request.runtime,
                        "boundary_type": parsed_request.boundary_type,
                        "mode": parsed_request.mode,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            ),
            raw_key_headers=idempotency_headers,
        )

        def mutation() -> CacheableTerminalOutcome:
            response = create_v1_boundary_response(
                parsed_request,
                identity=identity,
                service=cast(BoundaryAdminService, service),
                now=request_now,
            )
            return cacheable_json_outcome(response)

        _send_idempotent_mutation(handler, request, mutation)

    def _handle_auto_approval_rule_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
        idempotency_headers: tuple[str, ...] | None,
    ) -> None:
        body: object = None
        if method == "POST" and path == "/v1/auto-approval-rules":
            parsed = _read_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        headers = _authorization_headers(handler, "X-Workspace-Key")
        request_now = now()

        def mutate() -> V1HttpResponse:
            return handle_v1_auto_approval_rules_http(
                method=method,
                path=path,
                headers=headers,
                body=body,
                workspace_identities=workspace_keys,
                workspace_identity_resolver=resolve_workspace_identity,
                service=cast(AutoApprovalAdminService, service),
                now=request_now,
            )

        if idempotency_headers is None or method != "POST" or path != "/v1/auto-approval-rules":
            _send_json(handler, mutate())
            return
        scope = workspace_idempotency_scope(headers, request_now)
        if scope is None:
            _send_json(handler, mutate())
            return
        parsed_request = parse_v1_auto_approval_rule_create_body(body)
        if isinstance(parsed_request, V1HttpResponse):
            _send_json(handler, parsed_request)
            return
        identity = WorkspaceIdentity(workspace_id=scope.workspace_id)
        request = HttpIdempotencyRequest(
            fingerprint_input=RequestFingerprintInput(
                method="POST",
                path=path,
                authenticated_workspace_id=scope.workspace_id,
                authenticated_principal=scope.principal,
                operation="auto_approval_rule.create.v1",
                request_body=json.dumps(
                    {
                        "name": parsed_request.name,
                        "target_agent_id": parsed_request.target_agent_id,
                        "allowed_scopes": list(parsed_request.allowed_scopes),
                        "max_ttl_seconds": parsed_request.max_ttl_seconds,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            ),
            raw_key_headers=idempotency_headers,
        )

        def mutation() -> CacheableTerminalOutcome:
            response = create_v1_auto_approval_rule_response(
                parsed_request,
                identity=identity,
                service=cast(AutoApprovalAdminService, service),
                now=request_now,
            )
            return cacheable_json_outcome(response)

        _send_idempotent_mutation(handler, request, mutation)

    def _handle_grant_request_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
        idempotency_headers: tuple[str, ...] | None,
    ) -> None:
        body: object = None
        if method == "POST":
            parsed = _read_optional_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        headers = _authorization_headers(handler, "X-Workspace-Key")
        request_now = now()

        def mutate() -> V1HttpResponse:
            return handle_v1_grant_requests_http(
                method=method,
                path=path,
                headers=headers,
                body=body,
                agent_identities=agent_keys,
                workspace_identities=workspace_keys,
                agent_identity_resolver=agent_identity_resolver,
                workspace_identity_resolver=resolve_workspace_identity,
                service=cast(GrantRequestService, service),
                now=request_now,
            )

        operation = _grant_request_idempotency_operation(method, path)
        if idempotency_headers is None or operation is None:
            _send_json(handler, mutate())
            return
        scope = workspace_idempotency_scope(headers, request_now)
        if scope is None:
            _send_json(handler, mutate())
            return
        identity = WorkspaceIdentity(workspace_id=scope.workspace_id)
        parts = path.removeprefix("/v1/grant-requests/").split("/")
        request_id, action = parts
        if action == "auto-approve":
            parsed_auto_approve = parse_v1_grant_request_auto_approve_body(body)
            if isinstance(parsed_auto_approve, V1HttpResponse):
                _send_json(handler, parsed_auto_approve)
                return
            semantic_body = b""

            def mutation() -> CacheableTerminalOutcome:
                response = auto_approve_v1_grant_request_response(
                    service=cast(GrantRequestService, service),
                    request_id=request_id,
                    identity=identity,
                    now=request_now,
                )
                return cacheable_json_outcome(response)

        else:
            parsed_decision = parse_v1_grant_request_decision_body(body)
            if isinstance(parsed_decision, V1HttpResponse):
                _send_json(handler, parsed_decision)
                return
            decision_action: GrantRequestDecisionAction = (
                "approve" if action == "approve" else "reject"
            )
            semantic_body = json.dumps(
                {"decision_reason": parsed_decision.decision_reason},
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")

            def mutation() -> CacheableTerminalOutcome:
                response = decide_v1_grant_request_response(
                    service=cast(GrantRequestService, service),
                    request_id=request_id,
                    action=decision_action,
                    identity=identity,
                    parsed=parsed_decision,
                    now=request_now,
                )
                return cacheable_json_outcome(response)

        request = HttpIdempotencyRequest(
            fingerprint_input=RequestFingerprintInput(
                method="POST",
                path=path,
                authenticated_workspace_id=scope.workspace_id,
                authenticated_principal=scope.principal,
                operation=operation,
                request_body=semantic_body,
            ),
            raw_key_headers=idempotency_headers,
        )

        _send_idempotent_mutation(handler, request, mutation)

    def _handle_grant_request(
        handler: BaseHTTPRequestHandler,
        method: str,
        path: str,
        query_string: str,
        idempotency_headers: tuple[str, ...] | None,
    ) -> None:
        body: object = None
        if method == "POST" and path == "/v1/grants":
            parsed = _read_json_body(handler)
            if isinstance(parsed, V1HttpResponse):
                _send_json(handler, parsed)
                return
            body = parsed

        headers = _authorization_headers(handler, "X-Workspace-Key")
        request_now = now()

        def mutate() -> V1HttpResponse:
            return handle_v1_grants_http(
                method=method,
                path=path,
                headers=headers,
                body=body,
                query_string=query_string,
                workspace_identities=workspace_keys,
                workspace_identity_resolver=resolve_workspace_identity,
                service=cast(GrantLifecycleService, service),
                now=request_now,
            )

        if idempotency_headers is None or method != "POST" or path != "/v1/grants":
            _send_json(handler, mutate())
            return
        scope = workspace_idempotency_scope(headers, request_now)
        if scope is None:
            _send_json(handler, mutate())
            return
        parsed_request = parse_v1_grant_issue_body(body)
        if isinstance(parsed_request, V1HttpResponse):
            _send_json(handler, parsed_request)
            return
        identity = WorkspaceIdentity(workspace_id=scope.workspace_id)
        request = HttpIdempotencyRequest(
            fingerprint_input=RequestFingerprintInput(
                method="POST",
                path=path,
                authenticated_workspace_id=scope.workspace_id,
                authenticated_principal=scope.principal,
                operation="grant.issue.v1",
                request_body=json.dumps(
                    {
                        "agent_id": parsed_request.agent_id,
                        "scopes": list(parsed_request.scopes),
                        "ttl_seconds": parsed_request.ttl_seconds,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8"),
            ),
            raw_key_headers=idempotency_headers,
        )

        def mutation() -> CacheableTerminalOutcome:
            response = issue_v1_grant_response(
                parsed_request,
                identity=identity,
                service=cast(GrantLifecycleService, service),
                now=request_now,
            )
            return cacheable_json_outcome(response)

        _send_idempotent_mutation(handler, request, mutation)

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
            headers=_authorization_headers(handler, "X-Auditor-Key"),
            workspace_identities=workspace_keys,
            workspace_identity_resolver=resolve_workspace_identity,
            auditor_identities=auditor_keys,
            auditor_identity_resolver=resolve_auditor_identity,
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
            headers=_authorization_headers(handler, "X-Service-Operator-Key"),
            service_operator_keys=service_keys,
            service_operator_resolver=resolve_service_operator,
            service=cast(AuditReadService, service),
            now=now(),
        )
        _send_json(handler, response)

    # Exposed so create_v1_http_server can tie the readiness worker's lifetime
    # to the server's. Callers using this factory directly own closing it.
    V1Handler.readiness_probe = readiness_probe  # type: ignore[attr-defined]
    return V1Handler


def _authorization_headers(
    handler: BaseHTTPRequestHandler,
    target_header: str,
) -> dict[str, str]:
    headers = dict(handler.headers.items())
    normalized = {key.lower(): value for key, value in headers.items()}
    local_headers = {
        "x-workspace-key",
        "x-auditor-key",
        "x-service-operator-key",
        "x-agent-key",
    }
    if local_headers.intersection(normalized):
        return headers
    authorization = normalized.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() == "bearer" and separator and token and " " not in token:
        headers[target_header] = token
    return headers


def _grant_request_idempotency_operation(method: str, path: str) -> str | None:
    if method != "POST":
        return None
    prefix = "/v1/grant-requests/"
    if not path.startswith(prefix):
        return None
    parts = path.removeprefix(prefix).split("/")
    if len(parts) != 2 or not parts[0]:
        return None
    return {
        "approve": "grant_request.approve.v1",
        "reject": "grant_request.reject.v1",
        "auto-approve": "grant_request.auto_approve.v1",
    }.get(parts[1])


_EXACT_ROUTES = frozenset(
    {
        "/healthz",
        "/readyz",
        "/metrics",
        "/v1/enforce/delegated",
        "/v1/enforce",
        "/v1/observe",
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


def _resolve_trusted_proxies() -> tuple[IpNetwork, ...]:
    """Parse VINCTOR_TRUSTED_PROXIES once at handler construction.

    Invalid configuration trusts no proxy rather than partially applying the
    list or failing server construction.
    """
    try:
        return parse_trusted_proxy_cidrs(os.environ.get("VINCTOR_TRUSTED_PROXIES"))
    except (TypeError, ValueError):
        return ()


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
    _send_pre_serialized(
        handler,
        encode_json_response(response),
    )


def _send_pre_serialized(
    handler: BaseHTTPRequestHandler,
    response: PreSerializedHttpResponse,
) -> None:
    handler._vinctor_status = response.status_code  # type: ignore[attr-defined]
    handler._vinctor_decision = response.observation.decision  # type: ignore[attr-defined]
    handler._vinctor_error = response.observation.error_code  # type: ignore[attr-defined]
    handler.send_response(response.status_code)
    handler.send_header("Content-Type", response.content_type)
    handler.send_header("Content-Length", str(len(response.body)))
    handler.end_headers()
    handler.wfile.write(response.body)


def _send_rate_limited(handler: BaseHTTPRequestHandler) -> None:
    """Write the pre-auth 429 with a generic body and nothing else disclosed."""
    handler._vinctor_status = 429  # type: ignore[attr-defined]
    handler._vinctor_error = "rate_limited"  # type: ignore[attr-defined]
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
