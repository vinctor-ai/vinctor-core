from __future__ import annotations

from datetime import datetime, timedelta
from secrets import token_urlsafe
from typing import Protocol

from vinctor_core.models import AuditEvent, Decision, Grant
from vinctor_core.scope import is_valid_grant_scope, scope_subsumes
from vinctor_service.audit import AuditWriter
from vinctor_service.models import GrantIssueRequest, GrantIssueResult
from vinctor_service.repositories import GrantLifecycleRepository

ScopeBoundsListing = tuple[tuple[str, tuple[str, ...]], ...]

# Sensible short default applied when a grant is issued without an explicit TTL.
DEFAULT_TTL_SECONDS = 1800
# Hard upper bound on any issued grant TTL, independent of per-agent max-TTL bounds.
MAX_TTL_SECONDS_CEILING = 30 * 24 * 3600


class AgentIssuableScopeBoundsRepository(Protocol):
    def get_bounds(self, *, workspace_id: str, agent_id: str) -> tuple[str, ...] | None: ...

    def get_max_ttl_seconds(self, *, workspace_id: str, agent_id: str) -> int | None: ...

    def list_bounds_for_workspace(self, workspace_id: str) -> ScopeBoundsListing: ...

    def set_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        now: datetime,
    ) -> None: ...


class InMemoryAgentIssuableScopeBoundsRepository:
    def __init__(
        self,
        bounds: dict[tuple[str, str], tuple[str, ...]] | None = None,
    ) -> None:
        self._bounds = dict(bounds or {})
        self._max_ttl: dict[tuple[str, str], int] = {}

    def get_bounds(self, *, workspace_id: str, agent_id: str) -> tuple[str, ...] | None:
        return self._bounds.get((workspace_id, agent_id))

    def get_max_ttl_seconds(self, *, workspace_id: str, agent_id: str) -> int | None:
        return self._max_ttl.get((workspace_id, agent_id))

    def list_bounds_for_workspace(self, workspace_id: str) -> ScopeBoundsListing:
        return tuple(
            (agent_id, scopes)
            for (bound_workspace_id, agent_id), scopes in sorted(self._bounds.items())
            if bound_workspace_id == workspace_id
        )

    def set_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        now: datetime,
    ) -> None:
        validate_issuable_scope_bounds(scopes, max_ttl_seconds=max_ttl_seconds)
        self._bounds[(workspace_id, agent_id)] = scopes
        if max_ttl_seconds is None:
            self._max_ttl.pop((workspace_id, agent_id), None)
        else:
            self._max_ttl[(workspace_id, agent_id)] = max_ttl_seconds


def issue_grant(
    request: GrantIssueRequest,
    *,
    grant_repository: GrantLifecycleRepository,
    scope_bounds_repository: AgentIssuableScopeBoundsRepository,
    audit_writer: AuditWriter,
    now: datetime,
) -> GrantIssueResult:
    applied_ttl_seconds = request.ttl_seconds if request.ttl_seconds > 0 else DEFAULT_TTL_SECONDS
    invalid_reason = _validate_issue_request(request, applied_ttl_seconds)
    if invalid_reason is not None:
        return GrantIssueResult(status="rejected", reason=invalid_reason)

    bounds = scope_bounds_repository.get_bounds(
        workspace_id=request.workspace_id,
        agent_id=request.target_agent_id,
    )
    if bounds is None:
        return GrantIssueResult(status="rejected", reason="issuable_bounds_not_found")
    if any(not is_valid_grant_scope(scope) for scope in bounds):
        return GrantIssueResult(status="rejected", reason="invalid_issuable_scope_bound")
    if not _scopes_within_bounds(request.requested_scopes, bounds):
        return GrantIssueResult(status="rejected", reason="scope_outside_issuable_bounds")

    max_ttl_seconds = scope_bounds_repository.get_max_ttl_seconds(
        workspace_id=request.workspace_id,
        agent_id=request.target_agent_id,
    )
    if max_ttl_seconds is not None and applied_ttl_seconds > max_ttl_seconds:
        return GrantIssueResult(status="rejected", reason="ttl_exceeds_issuable_max")

    grant = Grant(
        grant_id=request.grant_id or _new_id("grnt"),
        grant_ref=request.grant_ref or _new_id("grt"),
        workspace_id=request.workspace_id,
        agent_id=request.target_agent_id,
        scopes=request.requested_scopes,
        status="active",
        expires_at=now + timedelta(seconds=applied_ttl_seconds),
    )
    try:
        grant_repository.insert(grant)
    except ValueError:
        return GrantIssueResult(status="rejected", reason="duplicate_grant_ref")

    audit_event = _grant_lifecycle_event(
        event_type="grant_issued",
        reason="grant_issued",
        grant=grant,
        action="issue_grant",
        resource=f"agent/{grant.agent_id}",
        scope_attempted=",".join(grant.scopes),
        now=now,
    )
    audit_writer.write(audit_event)
    return GrantIssueResult(
        status="issued",
        reason="grant_issued",
        grant=grant,
        audit_event_id=audit_event.event_id,
    )


def lookup_grant(
    *,
    grant_ref: str,
    workspace_id: str,
    grant_repository: GrantLifecycleRepository,
) -> Grant | None:
    grant = grant_repository.get_by_ref(grant_ref)
    if grant is None or grant.workspace_id != workspace_id:
        return None
    return grant


def list_grants(
    *,
    workspace_id: str,
    agent_id: str | None = None,
    status: str | None = None,
    grant_repository: GrantLifecycleRepository,
) -> tuple[Grant, ...]:
    return grant_repository.list_grants_for_workspace(
        workspace_id,
        agent_id=agent_id,
        status=status,
    )


def revoke_grant(
    *,
    grant_ref: str,
    workspace_id: str,
    grant_repository: GrantLifecycleRepository,
    audit_writer: AuditWriter,
    now: datetime,
) -> tuple[Grant, str] | None:
    grant = grant_repository.revoke(grant_ref=grant_ref, workspace_id=workspace_id)
    if grant is None:
        return None

    audit_event = _grant_lifecycle_event(
        event_type="grant_revoked",
        decision="deny",
        reason="grant_revoked",
        grant=grant,
        action="revoke_grant",
        resource=f"grant/{grant.grant_ref}",
        scope_attempted=",".join(grant.scopes),
        now=now,
    )
    audit_writer.write(audit_event)
    return grant, audit_event.event_id


def _validate_issue_request(request: GrantIssueRequest, applied_ttl_seconds: int) -> str | None:
    if request.workspace_id == "":
        return "invalid_workspace_id"
    if request.target_agent_id == "":
        return "invalid_agent_id"
    if request.ttl_seconds < 0:
        return "invalid_ttl"
    if applied_ttl_seconds > MAX_TTL_SECONDS_CEILING:
        return "ttl_exceeds_max"
    if not request.requested_scopes:
        return "missing_requested_scopes"
    if any(not is_valid_grant_scope(scope) for scope in request.requested_scopes):
        return "invalid_requested_scope"
    return None


def validate_issuable_scope_bounds(
    scopes: tuple[str, ...],
    *,
    max_ttl_seconds: int | None = None,
) -> None:
    if not scopes:
        raise ValueError("at least one issuable scope bound is required")
    invalid = [scope for scope in scopes if not is_valid_grant_scope(scope)]
    if invalid:
        raise ValueError(f"invalid issuable scope bound: {invalid[0]}")
    if max_ttl_seconds is not None and (
        max_ttl_seconds <= 0 or max_ttl_seconds > MAX_TTL_SECONDS_CEILING
    ):
        raise ValueError("max_ttl_seconds must be a positive integer within the TTL ceiling")


def _scopes_within_bounds(
    requested_scopes: tuple[str, ...],
    bounds: tuple[str, ...],
) -> bool:
    return all(
        any(scope_subsumes(bound, requested) for bound in bounds)
        for requested in requested_scopes
    )


def _grant_lifecycle_event(
    *,
    event_type: str,
    decision: Decision = "permit",
    reason: str,
    grant: Grant,
    action: str,
    resource: str,
    scope_attempted: str,
    now: datetime,
) -> AuditEvent:
    return AuditEvent(
        event_id=_new_id("evt"),
        event_type=event_type,
        decision=decision,
        reason=reason,
        workspace_id=grant.workspace_id,
        agent_id=grant.agent_id,
        grant_id=grant.grant_id,
        grant_ref=grant.grant_ref,
        action=action,
        resource=resource,
        scope_attempted=scope_attempted,
        scope_matched=None,
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=now,
    )


def _new_id(prefix: str) -> str:
    return f"{prefix}_{token_urlsafe(16)}"
