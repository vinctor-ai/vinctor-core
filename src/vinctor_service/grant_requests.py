from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from secrets import token_urlsafe

from vinctor_core.models import AuditEvent, Grant
from vinctor_core.scope import is_valid_grant_scope
from vinctor_service.audit import AuditWriter
from vinctor_service.grants import AgentIssuableScopeBoundsRepository, issue_grant
from vinctor_service.models import (
    GrantIssueRequest,
    GrantRequest,
    GrantRequestCreateRequest,
    GrantRequestCreateResult,
    GrantRequestDecisionResult,
)
from vinctor_service.repositories import GrantLifecycleRepository, GrantRequestRepository


def create_grant_request(
    request: GrantRequestCreateRequest,
    *,
    request_repository: GrantRequestRepository,
    audit_writer: AuditWriter,
    now: datetime,
) -> GrantRequestCreateResult:
    invalid_reason = _validate_create_request(request)
    if invalid_reason is not None:
        return GrantRequestCreateResult(status="rejected", reason=invalid_reason)

    target_agent_id = request.target_agent_id or request.requester_agent_id
    grant_request = GrantRequest(
        request_id=request.request_id or _new_id("grq"),
        workspace_id=request.workspace_id,
        requester_agent_id=request.requester_agent_id,
        target_agent_id=target_agent_id,
        requested_scopes=request.requested_scopes,
        requested_ttl_seconds=request.requested_ttl_seconds,
        reason=request.reason,
        status="pending",
        created_at=now,
    )
    try:
        request_repository.insert_request(grant_request)
    except ValueError:
        return GrantRequestCreateResult(status="rejected", reason="duplicate_request_id")

    audit_event = _request_lifecycle_event(
        event_type="grant_requested",
        reason="grant_requested",
        request=grant_request,
        action="request_grant",
        resource=f"agent/{target_agent_id}",
        now=now,
    )
    audit_writer.write(audit_event)
    return GrantRequestCreateResult(
        status="created",
        reason="grant_requested",
        request=grant_request,
        audit_event_id=audit_event.event_id,
    )


def approve_grant_request(
    *,
    request_id: str,
    workspace_id: str,
    decided_by: str,
    decision_reason: str | None,
    request_repository: GrantRequestRepository,
    grant_repository: GrantLifecycleRepository,
    scope_bounds_repository: AgentIssuableScopeBoundsRepository,
    audit_writer: AuditWriter,
    now: datetime,
) -> GrantRequestDecisionResult:
    grant_request = _get_pending_workspace_request(
        request_id=request_id,
        workspace_id=workspace_id,
        request_repository=request_repository,
    )
    if grant_request is None:
        return GrantRequestDecisionResult(status="failed", reason="grant_request_not_found")
    if grant_request.status != "pending":
        return GrantRequestDecisionResult(status="failed", reason="grant_request_not_pending")

    issued = issue_grant(
        GrantIssueRequest(
            workspace_id=grant_request.workspace_id,
            target_agent_id=grant_request.target_agent_id,
            requested_scopes=grant_request.requested_scopes,
            ttl_seconds=grant_request.requested_ttl_seconds,
        ),
        grant_repository=grant_repository,
        scope_bounds_repository=scope_bounds_repository,
        audit_writer=audit_writer,
        now=now,
    )
    if issued.status == "rejected" or issued.grant is None:
        return GrantRequestDecisionResult(status="failed", reason=issued.reason)

    updated = replace(
        grant_request,
        status="approved",
        decided_at=now,
        decided_by=decided_by,
        decision_reason=decision_reason,
        issued_grant_ref=issued.grant.grant_ref,
    )
    request_repository.update_request(updated)
    audit_event = _request_decision_event(
        event_type="grant_request_approved",
        reason="grant_request_approved",
        request=updated,
        grant=issued.grant,
        action="approve_grant_request",
        now=now,
    )
    audit_writer.write(audit_event)
    return GrantRequestDecisionResult(
        status="approved",
        reason="grant_request_approved",
        request=updated,
        grant=issued.grant,
        audit_event_id=audit_event.event_id,
    )


def reject_grant_request(
    *,
    request_id: str,
    workspace_id: str,
    decided_by: str,
    decision_reason: str | None,
    request_repository: GrantRequestRepository,
    audit_writer: AuditWriter,
    now: datetime,
) -> GrantRequestDecisionResult:
    grant_request = _get_pending_workspace_request(
        request_id=request_id,
        workspace_id=workspace_id,
        request_repository=request_repository,
    )
    if grant_request is None:
        return GrantRequestDecisionResult(status="failed", reason="grant_request_not_found")
    if grant_request.status != "pending":
        return GrantRequestDecisionResult(status="failed", reason="grant_request_not_pending")

    updated = replace(
        grant_request,
        status="rejected",
        decided_at=now,
        decided_by=decided_by,
        decision_reason=decision_reason,
    )
    request_repository.update_request(updated)
    audit_event = _request_lifecycle_event(
        event_type="grant_request_rejected",
        reason="grant_request_rejected",
        request=updated,
        action="reject_grant_request",
        resource=f"grant_request/{updated.request_id}",
        now=now,
    )
    audit_writer.write(audit_event)
    return GrantRequestDecisionResult(
        status="rejected",
        reason="grant_request_rejected",
        request=updated,
        audit_event_id=audit_event.event_id,
    )


def lookup_grant_request(
    *,
    request_id: str,
    workspace_id: str,
    request_repository: GrantRequestRepository,
) -> GrantRequest | None:
    request = request_repository.get_request(request_id)
    if request is None or request.workspace_id != workspace_id:
        return None
    return request


def list_grant_requests(
    *,
    workspace_id: str,
    request_repository: GrantRequestRepository,
) -> tuple[GrantRequest, ...]:
    return request_repository.list_requests_for_workspace(workspace_id)


def _validate_create_request(request: GrantRequestCreateRequest) -> str | None:
    if request.workspace_id == "":
        return "invalid_workspace_id"
    if request.requester_agent_id == "":
        return "invalid_requester_agent_id"
    if request.target_agent_id == "":
        return "invalid_target_agent_id"
    if request.requested_ttl_seconds <= 0:
        return "invalid_ttl"
    if not request.requested_scopes:
        return "missing_requested_scopes"
    if any(not is_valid_grant_scope(scope) for scope in request.requested_scopes):
        return "invalid_requested_scope"
    if request.reason == "":
        return "missing_reason"
    return None


def _get_pending_workspace_request(
    *,
    request_id: str,
    workspace_id: str,
    request_repository: GrantRequestRepository,
) -> GrantRequest | None:
    grant_request = lookup_grant_request(
        request_id=request_id,
        workspace_id=workspace_id,
        request_repository=request_repository,
    )
    if grant_request is None:
        return None
    return grant_request


def _request_lifecycle_event(
    *,
    event_type: str,
    reason: str,
    request: GrantRequest,
    action: str,
    resource: str,
    now: datetime,
) -> AuditEvent:
    return AuditEvent(
        event_id=_new_id("evt"),
        event_type=event_type,
        decision="permit",
        reason=reason,
        workspace_id=request.workspace_id,
        agent_id=request.requester_agent_id,
        grant_id=request.request_id,
        grant_ref=request.request_id,
        action=action,
        resource=resource,
        scope_attempted=",".join(request.requested_scopes),
        scope_matched=None,
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=now,
    )


def _request_decision_event(
    *,
    event_type: str,
    reason: str,
    request: GrantRequest,
    grant: Grant,
    action: str,
    now: datetime,
) -> AuditEvent:
    return AuditEvent(
        event_id=_new_id("evt"),
        event_type=event_type,
        decision="permit",
        reason=reason,
        workspace_id=request.workspace_id,
        agent_id=request.target_agent_id,
        grant_id=grant.grant_id,
        grant_ref=grant.grant_ref,
        action=action,
        resource=f"grant_request/{request.request_id}",
        scope_attempted=",".join(request.requested_scopes),
        scope_matched=None,
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=now,
    )


def _new_id(prefix: str) -> str:
    return f"{prefix}_{token_urlsafe(16)}"
