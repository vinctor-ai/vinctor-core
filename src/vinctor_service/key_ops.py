from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from vinctor_service.keys import LocalKeyRecord, SQLiteLocalKeyRepository


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


def rotate_workspace_key(
    repository: SQLiteLocalKeyRepository,
    *,
    workspace_id: str,
    now: datetime,
) -> RotationResult:
    """Mint a new workspace key and revoke the previously active workspace keys."""
    created = repository.create_workspace_key(workspace_id=workspace_id, now=now)
    revoked = _revoke_prior(
        repository,
        workspace_id=workspace_id,
        new_key_id=created.record.key_id,
        keep=lambda record: record.key_type == "workspace",
        now=now,
    )
    return RotationResult(
        raw_key=created.raw_key,
        new_key_id=created.record.key_id,
        revoked_key_ids=revoked,
    )


def rotate_agent_key(
    repository: SQLiteLocalKeyRepository,
    *,
    workspace_id: str,
    agent_id: str,
    now: datetime,
) -> RotationResult:
    """Mint a new agent key and revoke the previously active keys for that agent."""
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
    return RotationResult(
        raw_key=created.raw_key,
        new_key_id=created.record.key_id,
        revoked_key_ids=revoked,
    )


def _revoke_prior(
    repository: SQLiteLocalKeyRepository,
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
