from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Literal

from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.v1_http import AgentIdentity, PepIdentity


@contextmanager
def _key_write_scope(conn: sqlite3.Connection) -> Iterator[None]:
    """Join an already-open transaction, else run as a standalone commit.

    Lets a single write participate in an outer unit of work (e.g. an atomic
    key rotation) instead of committing on its own, while direct callers keep
    their previous self-committing behavior. Mirrors sqlite._write_scope.
    """
    if conn.in_transaction:
        yield
    else:
        with conn:
            yield

KeyType = Literal[
    "workspace", "auditor", "service_operator", "agent", "resource_server"
]
KeyStatus = Literal["active", "revoked"]

WORKSPACE_KEY_PREFIX = "wsk_"
AUDITOR_KEY_PREFIX = "auk_"
SERVICE_OPERATOR_KEY_PREFIX = "sok_"
AGENT_KEY_PREFIX = "aak_"
PEP_KEY_PREFIX = "pep_"


@dataclass(frozen=True)
class LocalKeyRecord:
    key_id: str
    key_type: KeyType
    workspace_id: str
    agent_id: str | None
    key_hash: str
    key_prefix: str
    status: KeyStatus
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


@dataclass(frozen=True)
class CreatedLocalKey:
    raw_key: str
    record: LocalKeyRecord


class SQLiteLocalKeyRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """One serialized unit of work for a multi-write key operation.

        BEGIN IMMEDIATE takes the write lock up front (serializing rotations
        across connections/processes); create/revoke join it via
        _key_write_scope, so a new key and the revocation of its predecessors
        commit together or not at all. Joins an already-open transaction.
        """
        if self._conn.in_transaction:
            yield
            return
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._conn.rollback()
            raise
        self._conn.commit()

    def create_workspace_key(
        self,
        *,
        workspace_id: str,
        raw_key: str | None = None,
        now: datetime | None = None,
        key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(WORKSPACE_KEY_PREFIX)
        _validate_prefix(key, WORKSPACE_KEY_PREFIX)
        record = self._create_key(
            key_type="workspace",
            workspace_id=workspace_id,
            agent_id=None,
            raw_key=key,
            now=now,
            key_id=key_id,
        )
        return CreatedLocalKey(raw_key=key, record=record)

    def create_agent_key(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        raw_key: str | None = None,
        now: datetime | None = None,
        key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(AGENT_KEY_PREFIX)
        _validate_prefix(key, AGENT_KEY_PREFIX)
        record = self._create_key(
            key_type="agent",
            workspace_id=workspace_id,
            agent_id=agent_id,
            raw_key=key,
            now=now,
            key_id=key_id,
        )
        return CreatedLocalKey(raw_key=key, record=record)

    def create_auditor_key(
        self,
        *,
        workspace_id: str,
        raw_key: str | None = None,
        now: datetime | None = None,
        key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(AUDITOR_KEY_PREFIX)
        _validate_prefix(key, AUDITOR_KEY_PREFIX)
        record = self._create_key(
            key_type="auditor",
            workspace_id=workspace_id,
            agent_id=None,
            raw_key=key,
            now=now,
            key_id=key_id,
        )
        return CreatedLocalKey(raw_key=key, record=record)

    def create_service_operator_key(
        self,
        *,
        raw_key: str | None = None,
        now: datetime | None = None,
        key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(SERVICE_OPERATOR_KEY_PREFIX)
        _validate_prefix(key, SERVICE_OPERATOR_KEY_PREFIX)
        record = self._create_key(
            key_type="service_operator",
            workspace_id="*",
            agent_id=None,
            raw_key=key,
            now=now,
            key_id=key_id,
        )
        return CreatedLocalKey(raw_key=key, record=record)

    def create_pep_key(
        self,
        *,
        workspace_id: str,
        pep_id: str,
        raw_key: str | None = None,
        now: datetime | None = None,
        key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(PEP_KEY_PREFIX)
        _validate_prefix(key, PEP_KEY_PREFIX)
        record = self._create_key(
            key_type="resource_server",
            workspace_id=workspace_id,
            agent_id=pep_id,
            raw_key=key,
            now=now,
            key_id=key_id,
        )
        return CreatedLocalKey(raw_key=key, record=record)

    def ensure_workspace_key(
        self,
        *,
        workspace_id: str,
        raw_key: str,
        now: datetime | None = None,
    ) -> LocalKeyRecord:
        _validate_prefix(raw_key, WORKSPACE_KEY_PREFIX)
        existing = self.get_by_raw_key(raw_key, touch=False)
        if existing is not None:
            _require_compatible(
                existing,
                key_type="workspace",
                workspace_id=workspace_id,
                agent_id=None,
            )
            return existing
        return self.create_workspace_key(
            workspace_id=workspace_id,
            raw_key=raw_key,
            now=now,
        ).record

    def ensure_agent_key(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        raw_key: str,
        now: datetime | None = None,
    ) -> LocalKeyRecord:
        _validate_prefix(raw_key, AGENT_KEY_PREFIX)
        existing = self.get_by_raw_key(raw_key, touch=False)
        if existing is not None:
            _require_compatible(
                existing,
                key_type="agent",
                workspace_id=workspace_id,
                agent_id=agent_id,
            )
            return existing
        return self.create_agent_key(
            workspace_id=workspace_id,
            agent_id=agent_id,
            raw_key=raw_key,
            now=now,
        ).record

    def ensure_pep_key(
        self,
        *,
        workspace_id: str,
        pep_id: str,
        raw_key: str,
        now: datetime | None = None,
    ) -> LocalKeyRecord:
        _validate_prefix(raw_key, PEP_KEY_PREFIX)
        existing = self.get_by_raw_key(raw_key, touch=False)
        if existing is not None:
            _require_compatible(
                existing,
                key_type="resource_server",
                workspace_id=workspace_id,
                agent_id=pep_id,
            )
            return existing
        return self.create_pep_key(
            workspace_id=workspace_id,
            pep_id=pep_id,
            raw_key=raw_key,
            now=now,
        ).record

    def get_by_raw_key(
        self,
        raw_key: str,
        *,
        now: datetime | None = None,
        touch: bool = True,
    ) -> LocalKeyRecord | None:
        row = self._conn.execute(
            """
            SELECT key_id, key_type, workspace_id, agent_id, key_hash,
                   key_prefix, status, created_at, last_used_at, revoked_at
            FROM local_keys
            WHERE key_hash = ?
            """,
            (_hash_key(raw_key),),
        ).fetchone()
        record = _record_from_row(row)
        if record is None or not touch or record.status != "active":
            return record

        used_at = now or datetime.now(UTC)
        with self._conn:
            self._conn.execute(
                """
                UPDATE local_keys
                SET last_used_at = ?
                WHERE key_id = ?
                """,
                (used_at.isoformat(), record.key_id),
            )
        return LocalKeyRecord(
            key_id=record.key_id,
            key_type=record.key_type,
            workspace_id=record.workspace_id,
            agent_id=record.agent_id,
            key_hash=record.key_hash,
            key_prefix=record.key_prefix,
            status=record.status,
            created_at=record.created_at,
            last_used_at=used_at,
            revoked_at=record.revoked_at,
        )

    def resolve_workspace_identity(
        self,
        raw_key: str,
        *,
        now: datetime | None = None,
    ) -> WorkspaceIdentity | None:
        record = self.get_by_raw_key(raw_key, now=now)
        if record is None or record.status != "active" or record.key_type != "workspace":
            return None
        return WorkspaceIdentity(workspace_id=record.workspace_id)

    def resolve_auditor_identity(
        self,
        raw_key: str,
        *,
        now: datetime | None = None,
    ) -> WorkspaceIdentity | None:
        record = self.get_by_raw_key(raw_key, now=now)
        if record is None or record.status != "active" or record.key_type != "auditor":
            return None
        return WorkspaceIdentity(workspace_id=record.workspace_id)

    def resolve_service_operator(
        self,
        raw_key: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        record = self.get_by_raw_key(raw_key, now=now)
        return bool(
            record is not None
            and record.status == "active"
            and record.key_type == "service_operator"
        )

    def resolve_agent_identity(
        self,
        raw_key: str,
        *,
        now: datetime | None = None,
    ) -> AgentIdentity | None:
        record = self.get_by_raw_key(raw_key, now=now)
        if (
            record is None
            or record.status != "active"
            or record.key_type != "agent"
            or record.agent_id is None
        ):
            return None
        return AgentIdentity(workspace_id=record.workspace_id, agent_id=record.agent_id)

    def resolve_pep_identity(
        self,
        raw_key: str,
        *,
        now: datetime | None = None,
    ) -> PepIdentity | None:
        record = self.get_by_raw_key(raw_key, now=now)
        if (
            record is None
            or record.status != "active"
            or record.key_type != "resource_server"
            or record.agent_id is None
        ):
            return None
        return PepIdentity(workspace_id=record.workspace_id, pep_id=record.agent_id)

    def revoke_key(
        self,
        key_id: str,
        *,
        now: datetime | None = None,
    ) -> LocalKeyRecord | None:
        record = self.get_by_id(key_id)
        if record is None:
            return None
        if record.status == "revoked":
            return record

        revoked_at = now or datetime.now(UTC)
        with _key_write_scope(self._conn):
            self._conn.execute(
                """
                UPDATE local_keys
                SET status = 'revoked', revoked_at = ?
                WHERE key_id = ?
                """,
                (revoked_at.isoformat(), key_id),
            )
        return LocalKeyRecord(
            key_id=record.key_id,
            key_type=record.key_type,
            workspace_id=record.workspace_id,
            agent_id=record.agent_id,
            key_hash=record.key_hash,
            key_prefix=record.key_prefix,
            status="revoked",
            created_at=record.created_at,
            last_used_at=record.last_used_at,
            revoked_at=revoked_at,
        )

    def get_by_id(self, key_id: str) -> LocalKeyRecord | None:
        row = self._conn.execute(
            """
            SELECT key_id, key_type, workspace_id, agent_id, key_hash,
                   key_prefix, status, created_at, last_used_at, revoked_at
            FROM local_keys
            WHERE key_id = ?
            """,
            (key_id,),
        ).fetchone()
        return _record_from_row(row)

    def list_for_workspace(self, workspace_id: str) -> tuple[LocalKeyRecord, ...]:
        rows = self._conn.execute(
            """
            SELECT key_id, key_type, workspace_id, agent_id, key_hash,
                   key_prefix, status, created_at, last_used_at, revoked_at
            FROM local_keys
            WHERE workspace_id = ?
            ORDER BY created_at, key_id
            """,
            (workspace_id,),
        ).fetchall()
        return tuple(record for row in rows if (record := _record_from_row(row)) is not None)

    def _create_key(
        self,
        *,
        key_type: KeyType,
        workspace_id: str,
        agent_id: str | None,
        raw_key: str,
        now: datetime | None,
        key_id: str | None,
    ) -> LocalKeyRecord:
        timestamp = now or datetime.now(UTC)
        record = LocalKeyRecord(
            key_id=key_id or _new_key("lkey_"),
            key_type=key_type,
            workspace_id=workspace_id,
            agent_id=agent_id,
            key_hash=_hash_key(raw_key),
            key_prefix=_key_prefix(raw_key),
            status="active",
            created_at=timestamp,
        )
        with _key_write_scope(self._conn):
            self._conn.execute(
                """
                INSERT INTO local_keys (
                    key_id, key_type, workspace_id, agent_id, key_hash,
                    key_prefix, status, created_at, last_used_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.key_id,
                    record.key_type,
                    record.workspace_id,
                    record.agent_id,
                    record.key_hash,
                    record.key_prefix,
                    record.status,
                    record.created_at.isoformat(),
                    None,
                    None,
                ),
            )
        return record


def mask_key(raw_key: str) -> str:
    if len(raw_key) <= 12:
        return raw_key
    return f"{raw_key[:8]}...{raw_key[-4:]}"


def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def _new_key(prefix: str) -> str:
    return f"{prefix}{token_urlsafe(24)}"


def _key_prefix(raw_key: str) -> str:
    prefix, separator, _ = raw_key.partition("_")
    return f"{prefix}{separator}" if separator else ""


def _validate_prefix(raw_key: str, expected_prefix: str) -> None:
    if not raw_key.startswith(expected_prefix):
        raise ValueError(f"key must start with {expected_prefix}")


def _require_compatible(
    record: LocalKeyRecord,
    *,
    key_type: KeyType,
    workspace_id: str,
    agent_id: str | None,
) -> None:
    if record.status != "active":
        raise ValueError("key is revoked")
    if (
        record.key_type != key_type
        or record.workspace_id != workspace_id
        or record.agent_id != agent_id
    ):
        raise ValueError("key has incompatible identity")


def _record_from_row(row: sqlite3.Row | tuple | None) -> LocalKeyRecord | None:
    if row is None:
        return None
    return LocalKeyRecord(
        key_id=row[0],
        key_type=row[1],
        workspace_id=row[2],
        agent_id=row[3],
        key_hash=row[4],
        key_prefix=row[5],
        status=row[6],
        created_at=datetime.fromisoformat(row[7]),
        last_used_at=datetime.fromisoformat(row[8]) if row[8] is not None else None,
        revoked_at=datetime.fromisoformat(row[9]) if row[9] is not None else None,
    )
