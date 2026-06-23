from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from secrets import token_urlsafe

from vinctor_core.audit import EVENT_SUBJECT_TOKEN_MINTED
from vinctor_core.models import AuditEvent, Grant
from vinctor_service.audit import AuditWriter
from vinctor_service.keys import _hash_key, _new_key
from vinctor_service.models import SubjectToken
from vinctor_service.repositories import GrantRepository, SubjectTokenRepository


@dataclass(frozen=True)
class SubjectTokenMintResult:
    status: str  # "minted" | "forbidden"
    token: str | None = None
    token_id: str | None = None
    expires_at: datetime | None = None


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
) -> SubjectTokenMintResult:
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
        return SubjectTokenMintResult(status="forbidden")

    expires_at = now + timedelta(seconds=ttl_seconds)
    if grant.expires_at is not None and grant.expires_at < expires_at:
        expires_at = grant.expires_at  # never outlive the grant

    raw_token = _new_key("vat_")
    token_id = _new_key("vtk_")
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
    )
    subject_token_repository.insert(token)
    audit_writer.write(_subject_token_minted_event(token=token, now=now))
    return SubjectTokenMintResult(
        status="minted", token=raw_token, token_id=token_id, expires_at=expires_at
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
