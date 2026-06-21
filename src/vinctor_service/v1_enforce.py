from __future__ import annotations

import contextlib
from datetime import datetime

from vinctor_core.audit import (
    REASON_AGENT_GRANT_MISMATCH,
    REASON_SUBJECT_TOKEN_INVALID,
    AuditEventInput,
    build_audit_event,
    build_rejection_audit_event,
)
from vinctor_core.enforce import evaluate_enforce
from vinctor_core.models import (
    AuditEvent,
    BoundaryLookup,
    DecisionResult,
    EnforceInput,
    Grant,
)
from vinctor_core.scope import is_valid_requested_action, is_valid_requested_resource
from vinctor_service.audit import AuditWriter
from vinctor_service.keys import _hash_key
from vinctor_service.models import (
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
    V1EnforceResponse,
)
from vinctor_service.repositories import GrantRepository, SubjectTokenRepository


def enforce_v1_contract(
    request: V1EnforceRequest,
    *,
    grant_repository: GrantRepository,
    now: datetime,
    audit_writer: AuditWriter,
    boundary_registry: BoundaryLookup | None = None,
) -> V1EnforceResponse:
    try:
        grant = grant_repository.get_by_ref(request.grant_ref)
    except Exception:
        return _pre_audit_error(
            503,
            "service_unavailable",
            "grant lookup failed; no decision was recorded",
        )

    if grant is None:
        return _pre_audit_error(
            404,
            "grant_not_found",
            f"grant_ref {request.grant_ref} does not exist",
        )

    if grant.workspace_id != request.workspace_id or grant.agent_id != request.agent_id:
        _record_rejection(
            audit_writer,
            reason_code=REASON_AGENT_GRANT_MISMATCH,
            workspace_id=request.workspace_id,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            boundary_id=request.boundary_id,
            now=now,
        )
        return _pre_audit_error(
            403,
            "forbidden",
            f"grant_ref {request.grant_ref} does not belong to the requesting agent",
        )

    return _evaluate_and_record(
        grant=grant,
        action=request.action,
        resource=request.resource,
        boundary_id=request.boundary_id,
        now=now,
        audit_writer=audit_writer,
        boundary_registry=boundary_registry,
    )


def delegated_enforce_v1_contract(
    request: V1DelegatedEnforceRequest,
    *,
    grant_repository: GrantRepository,
    now: datetime,
    audit_writer: AuditWriter,
    boundary_registry: BoundaryLookup | None = None,
    pep_workspace_id: str | None = None,
    subject_token_repository: SubjectTokenRepository | None = None,
) -> V1EnforceResponse:
    """Resolve an on-behalf-of enforce request from a PEP (see ADR 0007).

    The PEP authenticates with its own key; the trusted PEP workspace is derived
    only from that authenticated identity and the grant must belong to the
    asserted subject *in that trusted workspace*. This makes tenant isolation
    structural: a PEP can never authorize a subject or grant in another
    workspace, and the function fails closed when no trusted PEP workspace is
    supplied (it never falls back to the caller-asserted workspace). The
    enforcing PEP principal is recorded separately from the subject ``agent_id``
    in the audit trail.
    """
    # Trusted workspace comes ONLY from authenticated sources (the key-derived
    # identity forwarded by the HTTP handler, or an explicit trusted override).
    # We never fall back to request.workspace_id, which is caller-asserted and
    # could otherwise be used to authorize a grant in an arbitrary workspace.
    trusted_ws = pep_workspace_id or request.pep_workspace_id
    if not trusted_ws:
        # Fail closed: without a trusted PEP workspace identity we cannot
        # establish tenant isolation. Deny before any audit event is written
        # (mirrors the other pre-audit deny paths).
        return _pre_audit_error(
            403,
            "forbidden",
            "delegated enforce requires a trusted PEP workspace identity",
        )

    # A caller-asserted workspace, if present, must match the trusted workspace;
    # it can never override it.
    if request.workspace_id and request.workspace_id != trusted_ws:
        _record_rejection(
            audit_writer,
            reason_code=REASON_AGENT_GRANT_MISMATCH,
            workspace_id=trusted_ws,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            boundary_id=request.boundary_id,
            now=now,
            enforcing_principal=request.pep_id,
        )
        return _pre_audit_error(
            403,
            "forbidden",
            f"grant_ref {request.grant_ref} does not belong to the asserted subject",
        )

    try:
        grant = grant_repository.get_by_ref(request.grant_ref)
    except Exception:
        return _pre_audit_error(
            503,
            "service_unavailable",
            "grant lookup failed; no decision was recorded",
        )

    if grant is None:
        return _pre_audit_error(
            404,
            "grant_not_found",
            f"grant_ref {request.grant_ref} does not exist",
        )

    # Tenant isolation: authorize against the TRUSTED workspace, and require the
    # grant to belong to the asserted subject within it.
    if grant.workspace_id != trusted_ws or grant.agent_id != request.agent_id:
        _record_rejection(
            audit_writer,
            reason_code=REASON_AGENT_GRANT_MISMATCH,
            workspace_id=trusted_ws,
            agent_id=request.agent_id,
            action=request.action,
            resource=request.resource,
            boundary_id=request.boundary_id,
            now=now,
            enforcing_principal=request.pep_id,
        )
        return _pre_audit_error(
            403,
            "forbidden",
            f"grant_ref {request.grant_ref} does not belong to the asserted subject",
        )

    # ADR 0007 Model 2: proven-identity path. The token (if present) must agree
    # with the asserted body AND the resolved grant; any failure fails closed.
    # This block runs only after the grant is resolved and owned by the asserted
    # subject. Its lookup has its own try/except returning 403 -- never 503, and
    # it never falls back to the legacy asserted (unproven) path on error.
    identity_proven = False
    proven_token_id = None
    if request.subject_token is not None:
        try:
            token = (
                subject_token_repository.get_by_hash(_hash_key(request.subject_token))
                if subject_token_repository is not None
                else None
            )
        except Exception:
            token = None
        if token is None:
            _record_rejection(
                audit_writer,
                reason_code=REASON_SUBJECT_TOKEN_INVALID,
                workspace_id=trusted_ws,
                agent_id=request.agent_id,
                action=request.action,
                resource=request.resource,
                boundary_id=request.boundary_id,
                now=now,
                enforcing_principal=request.pep_id,
            )
            return _pre_audit_error(403, "forbidden", "subject token is not valid")
        # audience (target pep_id) + identity tuple (body and grant) + expiry
        if (
            token.expires_at <= now
            or token.audience != request.pep_id
            or token.workspace_id != trusted_ws
            or token.agent_id != request.agent_id
            or token.workspace_id != request.workspace_id
            or token.grant_ref != request.grant_ref
            or token.agent_id != grant.agent_id
            or token.workspace_id != grant.workspace_id
            or token.grant_ref != grant.grant_ref
        ):
            _record_rejection(
                audit_writer,
                reason_code=REASON_SUBJECT_TOKEN_INVALID,
                workspace_id=trusted_ws,
                agent_id=request.agent_id,
                action=request.action,
                resource=request.resource,
                boundary_id=request.boundary_id,
                now=now,
                enforcing_principal=request.pep_id,
            )
            return _pre_audit_error(403, "forbidden", "subject token is not valid")
        identity_proven = True
        proven_token_id = token.token_id

    return _evaluate_and_record(
        grant=grant,
        action=request.action,
        resource=request.resource,
        boundary_id=request.boundary_id,
        now=now,
        audit_writer=audit_writer,
        boundary_registry=boundary_registry,
        enforcing_principal=request.pep_id,
        identity_proven=identity_proven,
        token_id=proven_token_id,
    )


def _evaluate_and_record(
    *,
    grant: Grant,
    action: str,
    resource: str,
    boundary_id: str | None,
    now: datetime,
    audit_writer: AuditWriter,
    boundary_registry: BoundaryLookup | None,
    enforcing_principal: str | None = None,
    identity_proven: bool = False,
    token_id: str | None = None,
) -> V1EnforceResponse:
    if not is_valid_requested_action(action):
        return _pre_audit_error(
            400,
            "scope_invalid",
            _invalid_action_reason(action),
        )

    if not is_valid_requested_resource(resource):
        return _pre_audit_error(
            400,
            "scope_invalid",
            f"resource '{resource}' is not a valid v1 resource path",
        )

    decision = evaluate_enforce(
        EnforceInput(
            grant=grant,
            action=action,
            resource=resource,
            now=now,
            boundary_id=boundary_id,
            boundary_registry=boundary_registry,
        )
    )
    audit_event = build_audit_event(
        AuditEventInput(
            decision=decision,
            created_at=now,
            enforcing_principal=enforcing_principal,
            identity_proven=identity_proven,
            token_id=token_id,
        )
    )

    try:
        audit_writer.write(audit_event)
    except Exception:
        return _pre_audit_error(
            503,
            "service_unavailable",
            "audit write failed; no decision was recorded",
        )

    return _response_from_decision(decision, audit_event)


def _response_from_decision(
    decision: DecisionResult,
    audit_event: AuditEvent,
) -> V1EnforceResponse:
    if decision.decision == "permit":
        return V1EnforceResponse(
            status_code=200,
            decision="permit",
            grant_id=decision.grant_id,
            agent_id=decision.agent_id,
            scope_matched=decision.scope_matched,
            audit_event_id=audit_event.event_id,
        )

    return V1EnforceResponse(
        status_code=403,
        decision="deny",
        error=decision.reason,
        reason=_deny_reason(decision),
        grant_id=decision.grant_id,
        agent_id=decision.agent_id,
        audit_event_id=audit_event.event_id,
    )


def _pre_audit_error(status_code: int, error: str, reason: str) -> V1EnforceResponse:
    return V1EnforceResponse(status_code=status_code, error=error, reason=reason)


def _record_rejection(
    audit_writer: AuditWriter,
    *,
    reason_code: str,
    workspace_id: str,
    agent_id: str,
    action: str,
    resource: str,
    now: datetime,
    boundary_id: str | None = None,
    enforcing_principal: str | None = None,
) -> None:
    """Best-effort: record a pre-grant-evaluation rejection (ADR 0008).

    Never changes the caller-facing response: an audit-write failure here is
    swallowed so a security-relevant rejection still returns its generic,
    leak-free forbidden response (the access is denied regardless).
    """
    with contextlib.suppress(Exception):
        audit_writer.write(
            build_rejection_audit_event(
                reason_code=reason_code,
                workspace_id=workspace_id,
                agent_id=agent_id,
                action=action,
                resource=resource,
                created_at=now,
                boundary_id=boundary_id,
                enforcing_principal=enforcing_principal,
            )
        )


def _invalid_action_reason(action: str) -> str:
    if action == "push":
        return (
            "action 'push' is not a recognized v1 action verb; use 'write' for git push operations"
        )
    return f"action '{action}' is not a recognized v1 action verb"


def _deny_reason(decision: DecisionResult) -> str:
    if decision.reason == "action_denied":
        return f"scope {decision.scope_attempted} is not covered by grant {decision.grant_id}"
    if decision.reason == "grant_revoked":
        return f"grant {decision.grant_id} is revoked"
    if decision.reason == "grant_expired":
        return f"grant {decision.grant_id} is expired"
    if decision.reason == "grant_not_active":
        return f"grant {decision.grant_id} is not active"
    if decision.reason.startswith("boundary_"):
        boundary_id = decision.attempted_boundary_id or "unknown"
        return f"boundary {boundary_id} could not be used for this enforce request"
    return decision.reason
