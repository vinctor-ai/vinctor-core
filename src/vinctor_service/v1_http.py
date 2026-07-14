from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, cast

from vinctor_service.models import (
    ObservationClassification,
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
    V1EnforceResponse,
    V1ObserveRequest,
    V1ObserveResponse,
    V1SimulateRequest,
    V1SimulateResponse,
)
from vinctor_service.service_config import (
    DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
    DEFAULT_SUBJECT_TOKEN_TTL_SECONDS,
)


@dataclass(frozen=True)
class AgentIdentity:
    workspace_id: str
    agent_id: str


@dataclass(frozen=True)
class PepIdentity:
    """A Policy Enforcement Point (resource server) principal.

    A PEP authenticates with its own key and may ask Vinctor about a third-party
    subject. ``pep_id`` is the enforcing principal; it is never an ``agent_id``.
    """

    workspace_id: str
    pep_id: str


@dataclass(frozen=True)
class V1HttpResponse:
    status_code: int
    body: dict[str, Any]


class V1EnforceService(Protocol):
    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse: ...

    def record_auth_failure(
        self, *, surface: str, boundary_id: str | None, now: datetime
    ) -> None: ...


class V1ObserveService(Protocol):
    def observe(self, request: V1ObserveRequest, *, now: datetime) -> V1ObserveResponse: ...

    def record_auth_failure(
        self, *, surface: str, boundary_id: str | None, now: datetime
    ) -> None: ...


class V1SimulateService(Protocol):
    def simulate(self, request: V1SimulateRequest, *, now: datetime) -> V1SimulateResponse: ...

    def record_auth_failure(
        self, *, surface: str, boundary_id: str | None, now: datetime
    ) -> None: ...


class V1DelegatedEnforceService(Protocol):
    def delegated_enforce(
        self,
        request: V1DelegatedEnforceRequest,
        *,
        now: datetime,
        pop_skew_seconds: int = 30,
    ) -> V1EnforceResponse: ...

    def record_auth_failure(
        self, *, surface: str, boundary_id: str | None, now: datetime
    ) -> None: ...


class V1TokenService(Protocol):
    def mint_subject_token(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        grant_ref: str,
        audience: str,
        ttl_seconds: int,
        now: datetime,
        bound_action: str | None = None,
        bound_resource: str | None = None,
        pop: bool = False,
    ) -> Any: ...

    def record_auth_failure(
        self, *, surface: str, boundary_id: str | None, now: datetime
    ) -> None: ...


AgentIdentityResolver = Callable[[str, datetime], AgentIdentity | None]
PepIdentityResolver = Callable[[str, datetime], PepIdentity | None]


def handle_v1_enforce_http(
    *,
    headers: Mapping[str, str],
    body: object,
    agent_identities: Mapping[str, AgentIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    service: V1EnforceService,
    now: datetime,
) -> V1HttpResponse:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    agent_key = normalized_headers.get("x-agent-key")
    boundary_id = normalized_headers.get("x-vinctor-boundary-id")
    identity = (
        _resolve_agent_identity(
            agent_key,
            agent_identities=agent_identities,
            agent_identity_resolver=agent_identity_resolver,
            now=now,
        )
        if agent_key is not None
        else None
    )
    if identity is None:
        service.record_auth_failure(surface="enforce", boundary_id=boundary_id, now=now)
        return _error(401, "authentication_required", "valid X-Agent-Key header is required")

    parsed = _parse_enforce_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    request = V1EnforceRequest(
        workspace_id=identity.workspace_id,
        agent_id=identity.agent_id,
        grant_ref=parsed["grant_ref"],
        action=parsed["action"],
        resource=parsed["resource"],
        boundary_id=normalized_headers.get("x-vinctor-boundary-id"),
    )
    return _http_response_from_enforce(service.enforce(request, now=now))


def handle_v1_observe_http(
    *,
    headers: Mapping[str, str],
    body: object,
    agent_identities: Mapping[str, AgentIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    service: V1ObserveService,
    now: datetime,
) -> V1HttpResponse:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    agent_key = normalized_headers.get("x-agent-key")
    boundary_id = normalized_headers.get("x-vinctor-boundary-id")
    identity = (
        _resolve_agent_identity(
            agent_key,
            agent_identities=agent_identities,
            agent_identity_resolver=agent_identity_resolver,
            now=now,
        )
        if agent_key is not None
        else None
    )
    if identity is None:
        service.record_auth_failure(surface="observe", boundary_id=boundary_id, now=now)
        return _error(401, "authentication_required", "valid X-Agent-Key header is required")

    parsed = _parse_observe_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed
    response = service.observe(
        V1ObserveRequest(
            workspace_id=identity.workspace_id,
            agent_id=identity.agent_id,
            classification=cast(ObservationClassification, parsed["classification"]),
            action=parsed.get("action"),
            resource=parsed.get("resource"),
            boundary_id=boundary_id,
        ),
        now=now,
    )
    if response.status_code == 200:
        return V1HttpResponse(
            status_code=200,
            body={"status": "recorded", "audit_event_id": response.audit_event_id},
        )
    return _error(
        response.status_code,
        response.error or "service_unavailable",
        response.reason or "observation was not recorded",
    )


def handle_v1_simulate_http(
    *,
    headers: Mapping[str, str],
    body: object,
    agent_identities: Mapping[str, AgentIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    service: V1SimulateService,
    now: datetime,
) -> V1HttpResponse:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    agent_key = normalized_headers.get("x-agent-key")
    boundary_id = normalized_headers.get("x-vinctor-boundary-id")
    identity = (
        _resolve_agent_identity(
            agent_key,
            agent_identities=agent_identities,
            agent_identity_resolver=agent_identity_resolver,
            now=now,
        )
        if agent_key is not None
        else None
    )
    if identity is None:
        service.record_auth_failure(surface="simulate", boundary_id=boundary_id, now=now)
        return _error(401, "authentication_required", "valid X-Agent-Key header is required")

    parsed = _parse_enforce_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed
    response = service.simulate(
        V1SimulateRequest(
            workspace_id=identity.workspace_id,
            agent_id=identity.agent_id,
            grant_ref=parsed["grant_ref"],
            action=parsed["action"],
            resource=parsed["resource"],
            boundary_id=boundary_id,
        ),
        now=now,
    )
    if response.would_decision is not None:
        return V1HttpResponse(
            status_code=response.status_code,
            body={
                "status": "simulated",
                "would_decision": response.would_decision,
                "error": response.error,
                "reason": response.reason,
                "grant_id": response.grant_id,
                "agent_id": response.agent_id,
                "scope_matched": response.scope_matched,
                "audit_event_id": response.audit_event_id,
            },
        )
    return _error(
        response.status_code,
        response.error or "service_unavailable",
        response.reason or "simulation was not recorded",
    )


def handle_v1_delegated_enforce_http(
    *,
    headers: Mapping[str, str],
    body: object,
    pep_identities: Mapping[str, PepIdentity] | None = None,
    pep_identity_resolver: PepIdentityResolver | None = None,
    service: V1DelegatedEnforceService,
    now: datetime,
    pop_skew_seconds: int = 30,
) -> V1HttpResponse:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    pep_key = normalized_headers.get("x-pep-key")
    boundary_id = normalized_headers.get("x-vinctor-boundary-id")
    identity = (
        _resolve_pep_identity(
            pep_key,
            pep_identities=pep_identities,
            pep_identity_resolver=pep_identity_resolver,
            now=now,
        )
        if pep_key is not None
        else None
    )
    if identity is None:
        service.record_auth_failure(surface="delegated", boundary_id=boundary_id, now=now)
        return _error(401, "authentication_required", "valid X-PEP-Key header is required")

    parsed = _parse_delegated_enforce_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    request = V1DelegatedEnforceRequest(
        pep_id=identity.pep_id,
        workspace_id=parsed["workspace_id"],
        agent_id=parsed["agent_id"],
        grant_ref=parsed["grant_ref"],
        action=parsed["action"],
        resource=parsed["resource"],
        boundary_id=normalized_headers.get("x-vinctor-boundary-id"),
        pep_workspace_id=identity.workspace_id,
        subject_token=normalized_headers.get("x-subject-token"),
        subject_token_proof=normalized_headers.get("x-subject-token-proof"),
    )
    return _http_response_from_enforce(
        service.delegated_enforce(request, now=now, pop_skew_seconds=pop_skew_seconds)
    )


def handle_v1_tokens_http(
    *,
    headers: Mapping[str, str],
    body: object,
    agent_identities: Mapping[str, AgentIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    service: V1TokenService,
    now: datetime,
    max_ttl: int = DEFAULT_SUBJECT_TOKEN_MAX_TTL_SECONDS,
) -> V1HttpResponse:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    agent_key = normalized_headers.get("x-agent-key")
    identity = (
        _resolve_agent_identity(
            agent_key,
            agent_identities=agent_identities,
            agent_identity_resolver=agent_identity_resolver,
            now=now,
        )
        if agent_key is not None
        else None
    )
    if identity is None:
        service.record_auth_failure(surface="tokens", boundary_id=None, now=now)
        return _error(401, "authentication_required", "valid X-Agent-Key header is required")

    parsed = _parse_tokens_body(body, max_ttl=max_ttl)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    result = service.mint_subject_token(
        workspace_id=identity.workspace_id,
        agent_id=identity.agent_id,
        grant_ref=parsed["grant_ref"],
        audience=parsed["audience"],
        ttl_seconds=parsed["ttl_seconds"],
        now=now,
        bound_action=parsed["bound_action"],
        bound_resource=parsed["bound_resource"],
        pop=parsed["pop"],
    )
    if result.status != "minted":
        return _error(403, "forbidden", "subject token could not be issued")
    body = {
        "token": result.token,
        "token_id": result.token_id,
        "expires_at": result.expires_at.isoformat(),
    }
    if result.pop_secret is not None:
        body["pop_secret"] = result.pop_secret
    return V1HttpResponse(status_code=201, body=body)


def _parse_tokens_body(body: object, *, max_ttl: int) -> dict[str, Any] | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")
    extra = sorted(
        set(body) - {"grant_ref", "audience", "ttl_seconds", "action", "resource", "pop"}
    )
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")
    for field in ("grant_ref", "audience"):
        value = body.get(field)
        if not isinstance(value, str) or value == "":
            return _error(400, "invalid_request", f"{field} must be a non-empty string")
    ttl = body.get("ttl_seconds", DEFAULT_SUBJECT_TOKEN_TTL_SECONDS)
    if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl <= 0:
        return _error(400, "invalid_request", "ttl_seconds must be a positive integer")
    if ttl > max_ttl:
        return _error(400, "invalid_request", f"ttl_seconds exceeds maximum {max_ttl}")
    # Optional per-action binding: action + resource are both-or-neither, and each
    # must be a non-empty string when present.
    bound_action = body.get("action")
    bound_resource = body.get("resource")
    for field, value in (("action", bound_action), ("resource", bound_resource)):
        if value is not None and (not isinstance(value, str) or value == ""):
            return _error(400, "invalid_request", f"{field} must be a non-empty string")
    if (bound_action is None) != (bound_resource is None):
        return _error(
            400, "invalid_request", "action and resource must be set together"
        )
    # Optional HMAC proof-of-possession: must be a real bool (default off).
    pop = body.get("pop", False)
    if not isinstance(pop, bool):
        return _error(400, "invalid_request", "pop must be a boolean")
    return {
        "grant_ref": body["grant_ref"],
        "audience": body["audience"],
        "ttl_seconds": ttl,
        "bound_action": bound_action,
        "bound_resource": bound_resource,
        "pop": pop,
    }


def _resolve_agent_identity(
    agent_key: str,
    *,
    agent_identities: Mapping[str, AgentIdentity] | None,
    agent_identity_resolver: AgentIdentityResolver | None,
    now: datetime,
) -> AgentIdentity | None:
    if agent_identity_resolver is not None:
        return agent_identity_resolver(agent_key, now)
    return (agent_identities or {}).get(agent_key)


def _resolve_pep_identity(
    pep_key: str,
    *,
    pep_identities: Mapping[str, PepIdentity] | None,
    pep_identity_resolver: PepIdentityResolver | None,
    now: datetime,
) -> PepIdentity | None:
    if pep_identity_resolver is not None:
        return pep_identity_resolver(pep_key, now)
    return (pep_identities or {}).get(pep_key)


def _parse_enforce_body(body: object) -> dict[str, str] | V1HttpResponse:
    return _parse_string_body(body, required_fields={"grant_ref", "action", "resource"})


def _parse_observe_body(body: object) -> dict[str, str] | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")
    classification = body.get("classification")
    if classification == "mapped":
        required_fields = {"classification", "action", "resource"}
    elif classification == "unmapped":
        required_fields = {"classification"}
    else:
        return _error(400, "invalid_request", "classification must be mapped or unmapped")
    return _parse_string_body(body, required_fields=required_fields)


def _parse_delegated_enforce_body(body: object) -> dict[str, str] | V1HttpResponse:
    return _parse_string_body(
        body,
        required_fields={"workspace_id", "agent_id", "grant_ref", "action", "resource"},
    )


def _parse_string_body(
    body: object,
    *,
    required_fields: set[str],
) -> dict[str, str] | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")

    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields)
    if missing:
        return _error(400, "invalid_request", f"missing required field: {missing[0]}")
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")

    parsed: dict[str, str] = {}
    for field in sorted(required_fields):
        value = body[field]
        if not isinstance(value, str) or value == "":
            return _error(400, "invalid_request", f"{field} must be a non-empty string")
        parsed[field] = value
    return parsed


def _http_response_from_enforce(response: V1EnforceResponse) -> V1HttpResponse:
    if response.decision == "permit":
        return V1HttpResponse(
            status_code=response.status_code,
            body={
                "decision": "permit",
                "grant_id": response.grant_id,
                "agent_id": response.agent_id,
                "scope_matched": response.scope_matched,
                "audit_event_id": response.audit_event_id,
            },
        )

    if response.decision == "deny":
        return V1HttpResponse(
            status_code=response.status_code,
            body={
                "decision": "deny",
                "error": response.error,
                "reason": response.reason,
                "grant_id": response.grant_id,
                "agent_id": response.agent_id,
                "audit_event_id": response.audit_event_id,
            },
        )

    return _error(
        response.status_code,
        response.error or "service_unavailable",
        response.reason or "no decision was recorded",
    )


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})
