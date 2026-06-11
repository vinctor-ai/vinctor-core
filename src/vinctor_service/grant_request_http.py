from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from vinctor_core.models import Grant
from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.models import (
    AutoApprovalEvaluationResult,
    GrantRequest,
    GrantRequestCreateRequest,
    GrantRequestCreateResult,
    GrantRequestDecisionResult,
    GrantRequestRoutingHint,
)
from vinctor_service.v1_http import AgentIdentity, V1HttpResponse


class GrantRequestService(Protocol):
    def create_grant_request(
        self,
        request: GrantRequestCreateRequest,
        *,
        now: datetime,
    ) -> GrantRequestCreateResult: ...

    def lookup_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
    ) -> GrantRequest | None: ...

    def list_grant_requests(self, *, workspace_id: str) -> tuple[GrantRequest, ...]: ...

    def approve_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        decision_reason: str | None,
        now: datetime,
    ) -> GrantRequestDecisionResult: ...

    def reject_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        decision_reason: str | None,
        now: datetime,
    ) -> GrantRequestDecisionResult: ...

    def auto_approve_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        now: datetime,
    ) -> GrantRequestDecisionResult: ...

    def evaluate_auto_approval(
        self,
        *,
        request: GrantRequest,
    ) -> AutoApprovalEvaluationResult: ...


AgentIdentityResolver = Callable[[str, datetime], AgentIdentity | None]
WorkspaceIdentityResolver = Callable[[str, datetime], WorkspaceIdentity | None]


@dataclass(frozen=True)
class ParsedCreateRequestBody:
    scopes: tuple[str, ...]
    ttl_seconds: int
    reason: str
    task_id: str | None = None
    session_id: str | None = None
    boundary_id: str | None = None
    requester_runtime: str | None = None
    repo: str | None = None
    worktree: str | None = None


def handle_v1_grant_requests_http(
    *,
    method: str,
    path: str,
    headers: Mapping[str, str],
    body: object,
    agent_identities: Mapping[str, AgentIdentity] | None = None,
    workspace_identities: Mapping[str, WorkspaceIdentity] | None = None,
    agent_identity_resolver: AgentIdentityResolver | None = None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None = None,
    service: GrantRequestService,
    now: datetime,
) -> V1HttpResponse:
    if path == "/v1/grant-requests":
        if method == "POST":
            agent_identity = _agent_identity(
                headers,
                agent_identities=agent_identities,
                agent_identity_resolver=agent_identity_resolver,
                now=now,
            )
            if agent_identity is None:
                return _error(
                    401,
                    "authentication_required",
                    "valid X-Agent-Key header is required",
                )
            return _create_grant_request(
                body,
                identity=agent_identity,
                service=service,
                now=now,
            )

        workspace_identity = _workspace_identity(
            headers,
            workspace_identities=workspace_identities,
            workspace_identity_resolver=workspace_identity_resolver,
            now=now,
        )
        if workspace_identity is None:
            return _error(
                401,
                "authentication_required",
                "valid X-Workspace-Key header is required",
            )
        if method == "GET":
            return V1HttpResponse(
                status_code=200,
                body={
                    "grant_requests": [
                        _workspace_grant_request_body(service, request)
                        for request in service.list_grant_requests(
                            workspace_id=workspace_identity.workspace_id
                        )
                    ]
                },
            )
        return _error(
            405,
            "method_not_allowed",
            "GET or POST is required for /v1/grant-requests",
        )

    prefix = "/v1/grant-requests/"
    if path.startswith(prefix):
        workspace_identity = _workspace_identity(
            headers,
            workspace_identities=workspace_identities,
            workspace_identity_resolver=workspace_identity_resolver,
            now=now,
        )
        agent_identity = None
        if workspace_identity is None:
            agent_identity = _agent_identity(
                headers,
                agent_identities=agent_identities,
                agent_identity_resolver=agent_identity_resolver,
                now=now,
            )
            if agent_identity is None:
                return _error(
                    401,
                    "authentication_required",
                    "valid X-Workspace-Key or X-Agent-Key header is required",
                )

        suffix = path.removeprefix(prefix)
        parts = suffix.split("/")
        if len(parts) == 1 and parts[0] != "":
            if method != "GET":
                return _error(
                    405,
                    "method_not_allowed",
                    "GET is required for /v1/grant-requests/{request_id}",
                )
            workspace_id = (
                workspace_identity.workspace_id
                if workspace_identity is not None
                else agent_identity.workspace_id
            )
            request = service.lookup_grant_request(request_id=parts[0], workspace_id=workspace_id)
            if request is None:
                return _error(
                    404,
                    "grant_request_not_found",
                    "grant request was not found",
                )
            if workspace_identity is not None:
                return V1HttpResponse(
                    status_code=200,
                    body=_workspace_grant_request_body(service, request),
                )
            if agent_identity is not None and not _agent_can_view_request(
                agent_identity,
                request,
            ):
                return _error(
                    404,
                    "grant_request_not_found",
                    "grant request was not found",
                )
            return V1HttpResponse(status_code=200, body=_agent_grant_request_body(request))

        if len(parts) == 2 and parts[0] != "" and parts[1] in {
            "approve",
            "reject",
            "auto-approve",
        }:
            if workspace_identity is None:
                return _error(
                    401,
                    "authentication_required",
                    "valid X-Workspace-Key header is required",
                )
            if method != "POST":
                return _error(
                    405,
                    "method_not_allowed",
                    f"POST is required for /v1/grant-requests/{{request_id}}/{parts[1]}",
                )
            if parts[1] == "auto-approve":
                if body is not None:
                    return _error(
                        400,
                        "invalid_request",
                        "auto-approve request body must be empty",
                    )
                return _auto_approve_grant_request(
                    service=service,
                    request_id=parts[0],
                    identity=workspace_identity,
                    now=now,
                )
            decision_reason = _decision_reason(body)
            if isinstance(decision_reason, V1HttpResponse):
                return decision_reason
            return _decide_grant_request(
                service=service,
                request_id=parts[0],
                action=parts[1],
                identity=workspace_identity,
                decision_reason=decision_reason,
                now=now,
            )

        if suffix == "" or "/" in suffix:
            return _error(404, "not_found", "route not found")

    return _error(404, "not_found", "route not found")


def _create_grant_request(
    body: object,
    *,
    identity: AgentIdentity,
    service: GrantRequestService,
    now: datetime,
) -> V1HttpResponse:
    parsed = _parse_create_body(body)
    if isinstance(parsed, V1HttpResponse):
        return parsed

    result = service.create_grant_request(
        GrantRequestCreateRequest(
            workspace_id=identity.workspace_id,
            requester_agent_id=identity.agent_id,
            requested_scopes=parsed.scopes,
            requested_ttl_seconds=parsed.ttl_seconds,
            reason=parsed.reason,
            task_id=parsed.task_id,
            session_id=parsed.session_id,
            boundary_id=parsed.boundary_id,
            requester_runtime=parsed.requester_runtime,
            repo=parsed.repo,
            worktree=parsed.worktree,
        ),
        now=now,
    )
    if result.status == "rejected":
        return _error(400, result.reason, result.reason)
    if result.request is None:
        return _error(503, "service_unavailable", "grant request creation failed")
    return V1HttpResponse(
        status_code=201,
        body={
            **_grant_request_body(result.request),
            **_routing_hint_body(service, result.request),
            "audit_event_id": result.audit_event_id,
        },
    )


def _auto_approve_grant_request(
    *,
    service: GrantRequestService,
    request_id: str,
    identity: WorkspaceIdentity,
    now: datetime,
) -> V1HttpResponse:
    result = service.auto_approve_grant_request(
        request_id=request_id,
        workspace_id=identity.workspace_id,
        decided_by=f"workspace:{identity.workspace_id}",
        now=now,
    )

    if result.status == "failed":
        if result.reason == "grant_request_not_found":
            return _error(404, result.reason, result.reason)
        if result.reason in {
            "no_matching_rule",
            "scope_outside_rule",
            "ttl_exceeds_rule",
        }:
            if result.request is None:
                return _error(503, "service_unavailable", "auto-approval failed")
            return V1HttpResponse(
                status_code=200,
                body={
                    **_grant_request_body(result.request),
                    **_routing_hint_body(service, result.request),
                    "auto_approval": {
                        "decision": "would_not_approve",
                        "reason": result.reason,
                    },
                },
            )
        return _error(409, result.reason, result.reason)

    if result.request is None:
        return _error(503, "service_unavailable", "auto-approval failed")

    body = {
        **_grant_request_body(result.request),
        "audit_event_id": result.audit_event_id,
        "auto_approval": {
            "decision": "approved",
            "reason": result.reason,
            "rule_id": result.auto_approval_rule_id,
        },
    }
    if result.grant is not None:
        body["grant"] = _grant_body(result.grant)
    return V1HttpResponse(status_code=200, body=body)


def _decide_grant_request(
    *,
    service: GrantRequestService,
    request_id: str,
    action: str,
    identity: WorkspaceIdentity,
    decision_reason: str | None,
    now: datetime,
) -> V1HttpResponse:
    decided_by = f"workspace:{identity.workspace_id}"
    if action == "approve":
        result = service.approve_grant_request(
            request_id=request_id,
            workspace_id=identity.workspace_id,
            decided_by=decided_by,
            decision_reason=decision_reason,
            now=now,
        )
    else:
        result = service.reject_grant_request(
            request_id=request_id,
            workspace_id=identity.workspace_id,
            decided_by=decided_by,
            decision_reason=decision_reason,
            now=now,
        )

    if result.status == "failed":
        status_code = 404 if result.reason == "grant_request_not_found" else 409
        return _error(status_code, result.reason, result.reason)
    if result.request is None:
        return _error(503, "service_unavailable", "grant request decision failed")

    body = {
        **_grant_request_body(result.request),
        "audit_event_id": result.audit_event_id,
    }
    if result.grant is not None:
        body["grant"] = _grant_body(result.grant)
    return V1HttpResponse(status_code=200, body=body)


def _parse_create_body(body: object) -> ParsedCreateRequestBody | V1HttpResponse:
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")

    required_fields = {"scopes", "ttl_seconds", "reason"}
    optional_fields = {
        "task_id",
        "session_id",
        "boundary_id",
        "requester_runtime",
        "repo",
        "worktree",
    }
    body_fields = set(body)
    missing = sorted(required_fields - body_fields)
    extra = sorted(body_fields - required_fields - optional_fields)
    if missing:
        return _error(400, "invalid_request", f"missing required field: {missing[0]}")
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")

    scopes = body["scopes"]
    if not isinstance(scopes, list) or not scopes:
        return _error(400, "invalid_request", "scopes must be a non-empty array")
    if any(not isinstance(scope, str) or scope == "" for scope in scopes):
        return _error(400, "invalid_request", "scopes must contain only non-empty strings")

    ttl_seconds = body["ttl_seconds"]
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds <= 0:
        return _error(400, "invalid_request", "ttl_seconds must be a positive integer")

    reason = body["reason"]
    if not isinstance(reason, str) or reason == "":
        return _error(400, "invalid_request", "reason must be a non-empty string")

    metadata: dict[str, str | None] = {}
    for field_name in optional_fields:
        value = _optional_body_string(body, field_name)
        if isinstance(value, V1HttpResponse):
            return value
        metadata[field_name] = value

    return ParsedCreateRequestBody(
        scopes=tuple(scopes),
        ttl_seconds=ttl_seconds,
        reason=reason,
        task_id=metadata["task_id"],
        session_id=metadata["session_id"],
        boundary_id=metadata["boundary_id"],
        requester_runtime=metadata["requester_runtime"],
        repo=metadata["repo"],
        worktree=metadata["worktree"],
    )


def _decision_reason(body: object) -> str | None | V1HttpResponse:
    if body is None:
        return None
    if not isinstance(body, dict):
        return _error(400, "invalid_request", "request body must be a JSON object")
    extra = sorted(set(body) - {"decision_reason"})
    if extra:
        return _error(400, "invalid_request", f"unexpected field: {extra[0]}")
    value = body.get("decision_reason")
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        return _error(
            400,
            "invalid_request",
            "decision_reason must be a non-empty string when provided",
        )
    return value


def _optional_body_string(
    body: dict[str, object],
    field_name: str,
) -> str | None | V1HttpResponse:
    value = body.get(field_name)
    if value is None:
        return None
    if not isinstance(value, str) or value == "":
        return _error(
            400,
            "invalid_request",
            f"{field_name} must be a non-empty string when provided",
        )
    return value


def _agent_identity(
    headers: Mapping[str, str],
    *,
    agent_identities: Mapping[str, AgentIdentity] | None,
    agent_identity_resolver: AgentIdentityResolver | None,
    now: datetime,
) -> AgentIdentity | None:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    agent_key = normalized_headers.get("x-agent-key")
    if agent_key is None:
        return None
    if agent_identity_resolver is not None:
        return agent_identity_resolver(agent_key, now)
    return (agent_identities or {}).get(agent_key)


def _workspace_identity(
    headers: Mapping[str, str],
    *,
    workspace_identities: Mapping[str, WorkspaceIdentity] | None,
    workspace_identity_resolver: WorkspaceIdentityResolver | None,
    now: datetime,
) -> WorkspaceIdentity | None:
    normalized_headers = {key.lower(): value for key, value in headers.items()}
    workspace_key = normalized_headers.get("x-workspace-key")
    if workspace_key is None:
        return None
    if workspace_identity_resolver is not None:
        return workspace_identity_resolver(workspace_key, now)
    return (workspace_identities or {}).get(workspace_key)


def _grant_request_body(request: GrantRequest) -> dict[str, object]:
    return {
        "request_id": request.request_id,
        "workspace_id": request.workspace_id,
        "requester_agent_id": request.requester_agent_id,
        "target_agent_id": request.target_agent_id,
        "requested_scopes": list(request.requested_scopes),
        "requested_ttl_seconds": request.requested_ttl_seconds,
        "reason": request.reason,
        "status": request.status,
        "created_at": request.created_at.isoformat(),
        "decided_at": request.decided_at.isoformat()
        if request.decided_at is not None
        else None,
        "decided_by": request.decided_by,
        "decision_reason": request.decision_reason,
        "issued_grant_ref": request.issued_grant_ref,
        "task_id": request.task_id,
        "session_id": request.session_id,
        "boundary_id": request.boundary_id,
        "requester_runtime": request.requester_runtime,
        "repo": request.repo,
        "worktree": request.worktree,
    }


def _workspace_grant_request_body(
    service: GrantRequestService,
    request: GrantRequest,
) -> dict[str, object]:
    return {
        **_grant_request_body(request),
        **_routing_hint_body(service, request),
        "queue_reason": _queue_reason(service, request),
    }


def _agent_grant_request_body(request: GrantRequest) -> dict[str, object]:
    return {
        "request_id": request.request_id,
        "workspace_id": request.workspace_id,
        "requester_agent_id": request.requester_agent_id,
        "target_agent_id": request.target_agent_id,
        "requested_scopes": list(request.requested_scopes),
        "requested_ttl_seconds": request.requested_ttl_seconds,
        "reason": request.reason,
        "status": request.status,
        "created_at": request.created_at.isoformat(),
        "decided_at": request.decided_at.isoformat()
        if request.decided_at is not None
        else None,
        "decision_reason": request.decision_reason,
        "issued_grant_ref": request.issued_grant_ref,
        "task_id": request.task_id,
        "session_id": request.session_id,
        "boundary_id": request.boundary_id,
        "requester_runtime": request.requester_runtime,
        "repo": request.repo,
        "worktree": request.worktree,
    }


def _agent_can_view_request(identity: AgentIdentity, request: GrantRequest) -> bool:
    return (
        request.workspace_id == identity.workspace_id
        and identity.agent_id in {request.requester_agent_id, request.target_agent_id}
    )


def _routing_hint_body(
    service: GrantRequestService,
    request: GrantRequest,
) -> dict[str, object]:
    hint, reason = _routing_hint(service, request)
    return {
        "routing_hint": hint,
        "routing_reason": reason,
    }


def _routing_hint(
    service: GrantRequestService,
    request: GrantRequest,
) -> tuple[GrantRequestRoutingHint, str]:
    if request.status != "pending":
        return "pending_review", "grant_request_not_pending"

    evaluation = service.evaluate_auto_approval(request=request)
    if evaluation.decision == "would_approve":
        return "auto_approval_available", evaluation.reason
    return "manual_review_required", evaluation.reason


def _queue_reason(service: GrantRequestService, request: GrantRequest) -> str | None:
    if request.status == "pending":
        return _routing_hint(service, request)[1]
    return request.decision_reason


def _grant_body(grant: Grant) -> dict[str, object]:
    return {
        "grant_id": grant.grant_id,
        "grant_ref": grant.grant_ref,
        "workspace_id": grant.workspace_id,
        "agent_id": grant.agent_id,
        "scopes": list(grant.scopes),
        "status": grant.status,
        "expires_at": grant.expires_at.isoformat()
        if grant.expires_at is not None
        else None,
    }


def _error(status_code: int, error: str, reason: str) -> V1HttpResponse:
    return V1HttpResponse(status_code=status_code, body={"error": error, "reason": reason})
