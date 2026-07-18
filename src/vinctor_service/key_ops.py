from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from vinctor_core.audit import EVENT_KEY_REVOKED, EVENT_KEY_ROTATED
from vinctor_service.control_audit import ControlPlaneAuditor
from vinctor_service.keys import CreatedLocalKey, LocalKeyRecord


class KeyRotationRepository(Protocol):
    """The local-key repository surface a rotation needs — implemented by both
    SQLiteLocalKeyRepository and PostgresLocalKeyRepository, so rotation works on
    either backend (it used to be typed for the SQLite class only)."""

    def transaction(self) -> AbstractContextManager[None]: ...
    def list_for_workspace(self, workspace_id: str) -> tuple[LocalKeyRecord, ...]: ...
    def revoke_key(
        self, key_id: str, *, now: datetime | None = ...
    ) -> LocalKeyRecord | None: ...
    def get_by_id(self, key_id: str) -> LocalKeyRecord | None: ...
    def create_workspace_key(
        self, *, workspace_id: str, now: datetime | None = ...
    ) -> CreatedLocalKey: ...
    def create_auditor_key(
        self, *, workspace_id: str, now: datetime | None = ...
    ) -> CreatedLocalKey: ...
    def create_service_operator_key(
        self, *, now: datetime | None = ...
    ) -> CreatedLocalKey: ...
    def create_agent_key(
        self, *, workspace_id: str, agent_id: str, now: datetime | None = ...
    ) -> CreatedLocalKey: ...
    def create_pep_key(
        self, *, workspace_id: str, pep_id: str, now: datetime | None = ...
    ) -> CreatedLocalKey: ...


@dataclass(frozen=True)
class RotationResult:
    raw_key: str
    new_key_id: str
    revoked_key_ids: tuple[str, ...]


def serialize_key_record(record: LocalKeyRecord) -> dict[str, object]:
    """Render a key record as safe metadata. Never includes the key hash."""
    return {
        "key_id": record.key_id,
        "key_type": record.key_type,
        "workspace_id": record.workspace_id,
        "agent_id": record.agent_id,
        "key_prefix": record.key_prefix,
        "status": record.status,
        "created_at": record.created_at.isoformat(),
        "last_used_at": record.last_used_at.isoformat() if record.last_used_at else None,
        "revoked_at": record.revoked_at.isoformat() if record.revoked_at else None,
    }


def _record_rotation(
    control_auditor: ControlPlaneAuditor,
    *,
    action: str,
    created: CreatedLocalKey,
    revoked: tuple[str, ...],
    workspace_id: str,
    now: datetime,
    agent_id: str = "",
    enforcing_principal: str | None = None,
) -> None:
    """Write the rotation's ONE control event inside the rotation transaction
    (ADR 0019): the new key, the revocations, and the audit row commit — or
    unwind — together. Safe metadata only; never the plaintext or the hash."""
    control_auditor.record(
        event_type=EVENT_KEY_ROTATED,
        workspace_id=workspace_id,
        agent_id=agent_id,
        action=action,
        resource=f"key/{created.record.key_type}/{created.record.key_id}",
        reason=f"revoked={len(revoked)}",
        now=now,
        enforcing_principal=enforcing_principal,
    )


def revoke_local_key(
    repository: KeyRotationRepository,
    *,
    key_id: str,
    now: datetime,
    control_auditor: ControlPlaneAuditor,
    enforcing_principal: str | None = None,
) -> LocalKeyRecord | None:
    """Revoke one local key and audit it as ONE unit (PKA-56 B2).

    ``operator keys revoke`` used to call the repository's ``revoke_key``
    directly, so a revoked key left NO control event on the chain. This wrapper
    shares the repository's connection/transaction with the auditor (as
    rotation does), emits a ``key_revoked`` control event, and returns the
    revoked record — or ``None`` for an unknown key. An already-revoked key is
    idempotent: it returns the record and emits nothing, because no state
    changed. The per-key revokes a rotation performs internally are NOT routed
    through here, so a rotation still emits exactly one ``key_rotated`` event,
    never a ``key_revoked`` per predecessor.
    """
    # Fail closed BEFORE any write: the revoke and its control audit event are
    # one transaction only if the auditor writes through the repository's
    # connection.
    control_auditor.require_bound_to(getattr(repository, "_conn", None))
    with repository.transaction():
        existing = repository.get_by_id(key_id)
        if existing is None:
            return None
        if existing.status == "revoked":
            return existing
        record = repository.revoke_key(key_id, now=now)
        control_auditor.record(
            event_type=EVENT_KEY_REVOKED,
            workspace_id=existing.workspace_id,
            action="revoke_key",
            resource=f"key/{existing.key_type}/{key_id}",
            reason="status=revoked",
            now=now,
            enforcing_principal=enforcing_principal,
        )
        return record


def rotate_workspace_key(
    repository: KeyRotationRepository,
    *,
    workspace_id: str,
    now: datetime,
    control_auditor: ControlPlaneAuditor,
    enforcing_principal: str | None = None,
) -> RotationResult:
    """Mint a new workspace key and revoke the previously active workspace keys."""
    # Fail closed BEFORE any write: the rotation and its control audit event
    # are one transaction only if the auditor writes through the repository's
    # connection.
    control_auditor.require_bound_to(getattr(repository, "_conn", None))
    with repository.transaction():
        created = repository.create_workspace_key(workspace_id=workspace_id, now=now)
        revoked = _revoke_prior(
            repository,
            workspace_id=workspace_id,
            new_key_id=created.record.key_id,
            keep=lambda record: record.key_type == "workspace",
            now=now,
        )
        _record_rotation(
            control_auditor, action="rotate_workspace_key", created=created,
            revoked=revoked, workspace_id=workspace_id, now=now,
            enforcing_principal=enforcing_principal,
        )
    # Return the plaintext only after the rotation has committed.
    return RotationResult(
        raw_key=created.raw_key,
        new_key_id=created.record.key_id,
        revoked_key_ids=revoked,
    )


def rotate_auditor_key(
    repository: KeyRotationRepository,
    *,
    workspace_id: str,
    now: datetime,
    control_auditor: ControlPlaneAuditor,
    enforcing_principal: str | None = None,
) -> RotationResult:
    """Mint a new read-only auditor key and revoke prior auditor keys."""
    # Fail closed BEFORE any write: the rotation and its control audit event
    # are one transaction only if the auditor writes through the repository's
    # connection.
    control_auditor.require_bound_to(getattr(repository, "_conn", None))
    with repository.transaction():
        created = repository.create_auditor_key(workspace_id=workspace_id, now=now)
        revoked = _revoke_prior(
            repository,
            workspace_id=workspace_id,
            new_key_id=created.record.key_id,
            keep=lambda record: record.key_type == "auditor",
            now=now,
        )
        _record_rotation(
            control_auditor, action="rotate_auditor_key", created=created,
            revoked=revoked, workspace_id=workspace_id, now=now,
            enforcing_principal=enforcing_principal,
        )
    # Return the plaintext only after the rotation has committed.
    return RotationResult(
        raw_key=created.raw_key,
        new_key_id=created.record.key_id,
        revoked_key_ids=revoked,
    )


def rotate_service_operator_key(
    repository: KeyRotationRepository,
    *,
    now: datetime,
    control_auditor: ControlPlaneAuditor,
    enforcing_principal: str | None = None,
) -> RotationResult:
    """Mint one global service-operator key and revoke its predecessors."""
    # Fail closed BEFORE any write: the rotation and its control audit event
    # are one transaction only if the auditor writes through the repository's
    # connection.
    control_auditor.require_bound_to(getattr(repository, "_conn", None))
    with repository.transaction():
        created = repository.create_service_operator_key(now=now)
        revoked = _revoke_prior(
            repository,
            workspace_id="*",
            new_key_id=created.record.key_id,
            keep=lambda record: record.key_type == "service_operator",
            now=now,
        )
        # Service-operator keys are service-scoped: recorded under the same
        # "*" pseudo-workspace their key rows use.
        _record_rotation(
            control_auditor, action="rotate_service_operator_key", created=created,
            revoked=revoked, workspace_id="*", now=now,
            enforcing_principal=enforcing_principal,
        )
    # Return the plaintext only after the rotation has committed.
    return RotationResult(
        raw_key=created.raw_key,
        new_key_id=created.record.key_id,
        revoked_key_ids=revoked,
    )


def rotate_agent_key(
    repository: KeyRotationRepository,
    *,
    workspace_id: str,
    agent_id: str,
    now: datetime,
    control_auditor: ControlPlaneAuditor,
    enforcing_principal: str | None = None,
) -> RotationResult:
    """Mint a new agent key and revoke the previously active keys for that agent."""
    # Fail closed BEFORE any write: the rotation and its control audit event
    # are one transaction only if the auditor writes through the repository's
    # connection.
    control_auditor.require_bound_to(getattr(repository, "_conn", None))
    with repository.transaction():
        created = repository.create_agent_key(
            workspace_id=workspace_id,
            agent_id=agent_id,
            now=now,
        )
        revoked = _revoke_prior(
            repository,
            workspace_id=workspace_id,
            new_key_id=created.record.key_id,
            keep=lambda record: record.key_type == "agent" and record.agent_id == agent_id,
            now=now,
        )
        _record_rotation(
            control_auditor, action="rotate_agent_key", created=created,
            revoked=revoked, workspace_id=workspace_id, agent_id=agent_id, now=now,
            enforcing_principal=enforcing_principal,
        )
    # Return the plaintext only after the rotation has committed.
    return RotationResult(
        raw_key=created.raw_key,
        new_key_id=created.record.key_id,
        revoked_key_ids=revoked,
    )


def rotate_pep_key(
    repository: KeyRotationRepository,
    *,
    workspace_id: str,
    pep_id: str,
    now: datetime,
    control_auditor: ControlPlaneAuditor,
    enforcing_principal: str | None = None,
) -> RotationResult:
    """Mint a new PEP (resource-server) key and revoke prior keys for that PEP."""
    # Fail closed BEFORE any write: the rotation and its control audit event
    # are one transaction only if the auditor writes through the repository's
    # connection.
    control_auditor.require_bound_to(getattr(repository, "_conn", None))
    with repository.transaction():
        created = repository.create_pep_key(
            workspace_id=workspace_id,
            pep_id=pep_id,
            now=now,
        )
        revoked = _revoke_prior(
            repository,
            workspace_id=workspace_id,
            new_key_id=created.record.key_id,
            keep=lambda record: record.key_type == "resource_server" and record.agent_id == pep_id,
            now=now,
        )
        _record_rotation(
            control_auditor, action="rotate_pep_key", created=created,
            revoked=revoked, workspace_id=workspace_id, agent_id=pep_id, now=now,
            enforcing_principal=enforcing_principal,
        )
    # Return the plaintext only after the rotation has committed.
    return RotationResult(
        raw_key=created.raw_key,
        new_key_id=created.record.key_id,
        revoked_key_ids=revoked,
    )


def _revoke_prior(
    repository: KeyRotationRepository,
    *,
    workspace_id: str,
    new_key_id: str,
    keep,
    now: datetime,
) -> tuple[str, ...]:
    revoked = []
    for record in repository.list_for_workspace(workspace_id):
        if record.key_id == new_key_id or record.status != "active" or not keep(record):
            continue
        repository.revoke_key(record.key_id, now=now)
        revoked.append(record.key_id)
    return tuple(revoked)
