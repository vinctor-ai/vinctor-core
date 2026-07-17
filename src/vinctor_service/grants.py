from __future__ import annotations

import contextlib
from datetime import datetime, timedelta
from secrets import token_urlsafe
from typing import Protocol

from vinctor_core.audit import (
    EVENT_GRANT_ISSUE_REJECTED,
    REASON_ISSUABLE_BOUNDS_NOT_FOUND,
    REASON_SCOPE_OUTSIDE_ISSUABLE_BOUNDS,
    REASON_TTL_EXCEEDS_ISSUABLE_MAX,
    build_rejection_audit_event,
)
from vinctor_core.models import AuditEvent, Decision, Grant
from vinctor_core.scope import is_valid_grant_scope, scope_subsumes
from vinctor_service.audit import AuditWriter
from vinctor_service.models import AgentIssuableBounds, GrantIssueRequest, GrantIssueResult
from vinctor_service.repositories import GrantLifecycleRepository

ScopeBoundsListing = tuple[tuple[str, tuple[str, ...]], ...]

# Sensible short default applied when a grant is issued without an explicit TTL.
DEFAULT_TTL_SECONDS = 1800
# Hard upper bound on any issued grant TTL, independent of per-agent max-TTL bounds.
MAX_TTL_SECONDS_CEILING = 30 * 24 * 3600


class AgentIssuableScopeBoundsRepository(Protocol):
    def get_bounds(self, *, workspace_id: str, agent_id: str) -> tuple[str, ...] | None: ...

    def get_max_ttl_seconds(self, *, workspace_id: str, agent_id: str) -> int | None: ...

    def get_bounds_with_max_ttl(
        self, *, workspace_id: str, agent_id: str
    ) -> AgentIssuableBounds | None: ...

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
        # One immutable AgentIssuableBounds per key: scopes and max TTL are read
        # and written as a single value, so a concurrent set_bounds cannot
        # produce a torn (old-scopes, new-ttl) snapshot. A single dict get/set
        # is atomic under the GIL, so no explicit lock is needed.
        self._bounds: dict[tuple[str, str], AgentIssuableBounds] = {
            key: AgentIssuableBounds(scopes=scopes, max_ttl_seconds=None)
            for key, scopes in (bounds or {}).items()
        }

    def get_bounds(self, *, workspace_id: str, agent_id: str) -> tuple[str, ...] | None:
        entry = self._bounds.get((workspace_id, agent_id))
        return entry.scopes if entry is not None else None

    def get_max_ttl_seconds(self, *, workspace_id: str, agent_id: str) -> int | None:
        entry = self._bounds.get((workspace_id, agent_id))
        return entry.max_ttl_seconds if entry is not None else None

    def get_bounds_with_max_ttl(
        self, *, workspace_id: str, agent_id: str
    ) -> AgentIssuableBounds | None:
        return self._bounds.get((workspace_id, agent_id))

    def list_bounds_for_workspace(self, workspace_id: str) -> ScopeBoundsListing:
        return tuple(
            (agent_id, entry.scopes)
            for (bound_workspace_id, agent_id), entry in sorted(self._bounds.items())
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
        # Single atomic dict write of the combined value.
        self._bounds[(workspace_id, agent_id)] = AgentIssuableBounds(
            scopes=scopes, max_ttl_seconds=max_ttl_seconds
        )


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

    issuable = scope_bounds_repository.get_bounds_with_max_ttl(
        workspace_id=request.workspace_id,
        agent_id=request.target_agent_id,
    )
    if issuable is None:
        _record_issue_rejection(audit_writer, request, REASON_ISSUABLE_BOUNDS_NOT_FOUND, now)
        return GrantIssueResult(
            status="rejected",
            reason="issuable_bounds_not_found",
            detail=(
                f"no issuable scope bounds are configured for agent "
                f"'{request.target_agent_id}'"
            ),
        )
    # Scopes and max TTL come from ONE consistent snapshot of the bounds row,
    # so a concurrent set_bounds cannot produce a torn (old-scopes, new-ttl)
    # validation. Both checks below read from this single snapshot.
    bounds = issuable.scopes
    if any(not is_valid_grant_scope(scope) for scope in bounds):
        return GrantIssueResult(status="rejected", reason="invalid_issuable_scope_bound")
    outside = _scopes_outside_bounds(request.requested_scopes, bounds)
    if outside:
        _record_issue_rejection(audit_writer, request, REASON_SCOPE_OUTSIDE_ISSUABLE_BOUNDS, now)
        return GrantIssueResult(
            status="rejected",
            reason="scope_outside_issuable_bounds",
            detail=(
                f"requested scope(s) {', '.join(outside)} are outside agent "
                f"'{request.target_agent_id}' issuable bounds ({', '.join(bounds)})"
            ),
        )

    max_ttl_seconds = issuable.max_ttl_seconds
    if max_ttl_seconds is not None and applied_ttl_seconds > max_ttl_seconds:
        _record_issue_rejection(audit_writer, request, REASON_TTL_EXCEEDS_ISSUABLE_MAX, now)
        return GrantIssueResult(
            status="rejected",
            reason="ttl_exceeds_issuable_max",
            detail=(
                f"requested TTL {applied_ttl_seconds}s exceeds the max issuable TTL "
                f"{max_ttl_seconds}s for agent '{request.target_agent_id}'"
            ),
        )

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


def _record_issue_rejection(
    audit_writer: AuditWriter,
    request: GrantIssueRequest,
    reason_code: str,
    now: datetime,
) -> None:
    """Best-effort: record an out-of-bounds grant-issuance rejection (ADR 0008).

    Attributable to the operator's workspace and the target agent; records the
    requested scopes (not secret) and discloses no grant id. Never affects the
    issuance result.
    """
    with contextlib.suppress(Exception):
        audit_writer.write(
            build_rejection_audit_event(
                reason_code=reason_code,
                workspace_id=request.workspace_id,
                agent_id=request.target_agent_id,
                created_at=now,
                event_type=EVENT_GRANT_ISSUE_REJECTED,
                action="issue_grant",
                resource=f"agent/{request.target_agent_id}",
                scope_attempted=",".join(request.requested_scopes),
            )
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


def _scopes_outside_bounds(
    requested_scopes: tuple[str, ...],
    bounds: tuple[str, ...],
) -> tuple[str, ...]:
    return tuple(
        requested
        for requested in requested_scopes
        if not any(scope_subsumes(bound, requested) for bound in bounds)
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
