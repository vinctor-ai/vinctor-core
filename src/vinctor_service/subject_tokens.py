from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timedelta
from secrets import token_urlsafe

from vinctor_core.audit import (
    EVENT_SUBJECT_TOKEN_MINTED,
    REASON_AGENT_GRANT_MISMATCH,
    build_rejection_audit_event,
)
from vinctor_core.models import AuditEvent, Grant
from vinctor_service.audit import AuditWriter, record_rejection
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken
from vinctor_service.repositories import GrantRepository, SubjectTokenRepository


@dataclass(frozen=True)
class SubjectTokenMintResult:
    status: str  # "minted" | "forbidden"
    token: str | None = None
    token_id: str | None = None
    expires_at: datetime | None = None
    pop_secret: str | None = None  # returned once, only when minted with pop=True


def _grant_is_valid(grant: Grant, now: datetime) -> bool:
    # Mirror evaluate_enforce's validity (vinctor_core/enforce.py): status is
    # never flipped to 'expired', so a status=='active' grant past expires_at is
    # still 'active' — we must check expires_at explicitly.
    if grant.status in {"revoked", "expired"} or grant.status != "active":
        return False
    return not (grant.expires_at is not None and grant.expires_at <= now)


def mint_subject_token(
    *,
    grant_repository: GrantRepository,
    subject_token_repository: SubjectTokenRepository,
    audit_writer: AuditWriter,
    workspace_id: str,
    agent_id: str,
    grant_ref: str,
    audience: str,
    ttl_seconds: int,
    now: datetime,
    bound_action: str | None = None,
    bound_resource: str | None = None,
    pop: bool = False,
    atomic: Callable[[], AbstractContextManager[object]] = nullcontext,
) -> SubjectTokenMintResult:
    # ``atomic`` opens the all-or-nothing transaction that binds the successful
    # mint's state write (token insert) and its ``subject_token_minted`` audit row
    # together — the SQLite/Postgres services pass their real transaction scope;
    # in-memory (and direct callers) use the default no-op. The FORBIDDEN
    # rejection audit deliberately runs OUTSIDE it (see below).
    #
    # Both-or-neither: a binding is an (action, resource) pair. Reject a half
    # binding before any grant lookup or audit write (contract-level ValueError;
    # the HTTP layer maps this to 400 invalid_request).
    if (bound_action is None) != (bound_resource is None):
        raise ValueError("bound_action and bound_resource must be set together")

    grant = grant_repository.get_by_ref(grant_ref)
    # Hand-rolled ownership equality (NOT lookup_grant, which omits agent_id).
    if (
        grant is None
        or grant.agent_id != agent_id
        or grant.workspace_id != workspace_id
        or not _grant_is_valid(grant, now)
    ):
        # ADR 0008: the caller still gets only the generic forbidden below (no
        # oracle), but the probe is no longer invisible to the operator — mirror
        # the enforce/simulate mismatch paths EXACTLY. ONE identical event for
        # every deny cause (unknown ref, foreign grant, revoked/expired grant):
        # its fields derive only from the request, and the single write happens on
        # all branches of this collapsed condition, so auditing introduces no
        # timing or side-effect oracle between the cases. Attribution is the
        # caller's own authenticated identity (workspace_id/agent_id are
        # key-derived by the HTTP handler), and grant_id/grant_ref stay empty so
        # the probed ref is never echoed into the trail.
        #
        # This rejection audit runs OUTSIDE ``atomic`` — a standalone best-effort
        # write, structurally identical to enforce/simulate's ``record_rejection``
        # (self-committing scope, exception suppressed). No state is written on
        # this path, so there is nothing to be atomic with; keeping it out of the
        # mint transaction means an audit-store failure (or its commit) never
        # turns the generic forbidden into an error, and the forbidden path opens
        # no fallible outer commit of its own.
        record_rejection(
            audit_writer,
            build_rejection_audit_event(
                reason_code=REASON_AGENT_GRANT_MISMATCH,
                workspace_id=workspace_id,
                agent_id=agent_id,
                created_at=now,
                action="mint_subject_token",
                resource=f"audience/{audience}",
                scope_attempted=(
                    f"{bound_action}:{bound_resource}" if bound_action is not None else ""
                ),
            ),
        )
        return SubjectTokenMintResult(status="forbidden")

    expires_at = now + timedelta(seconds=ttl_seconds)
    if grant.expires_at is not None and grant.expires_at < expires_at:
        expires_at = grant.expires_at  # never outlive the grant

    raw_token = _new_key("vat_")
    token_id = _new_key("vtk_")
    pop_secret = token_urlsafe(32) if pop else None
    token = SubjectToken(
        token_id=token_id,
        token_hash=_hash_key(raw_token),
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_ref=grant_ref,
        audience=audience,
        issued_at=now,
        expires_at=expires_at,
        created_by=agent_id,
        bound_action=bound_action,
        bound_resource=bound_resource,
        pop_secret=pop_secret,
    )
    with atomic():
        subject_token_repository.insert(token)
        audit_writer.write(_subject_token_minted_event(token=token, now=now))
    return SubjectTokenMintResult(
        status="minted",
        token=raw_token,
        token_id=token_id,
        expires_at=expires_at,
        pop_secret=pop_secret,
    )


def _subject_token_minted_event(*, token: SubjectToken, now: datetime) -> AuditEvent:
    return AuditEvent(
        event_id=f"evt_{token_urlsafe(16)}",
        event_type=EVENT_SUBJECT_TOKEN_MINTED,
        decision="permit",
        reason=EVENT_SUBJECT_TOKEN_MINTED,
        workspace_id=token.workspace_id,
        agent_id=token.agent_id,
        grant_id="",
        grant_ref=token.grant_ref,
        action="",
        resource="",
        scope_attempted="",
        scope_matched=None,
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=now,
        token_id=token.token_id,
    )
