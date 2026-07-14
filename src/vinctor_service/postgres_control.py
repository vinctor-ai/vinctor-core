from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Any

from vinctor_service.boundary_http import WorkspaceIdentity
from vinctor_service.keys import (
    AGENT_KEY_PREFIX,
    PEP_KEY_PREFIX,
    WORKSPACE_KEY_PREFIX,
    CreatedLocalKey,
    KeyType,
    LocalKeyRecord,
)
from vinctor_service.models import GrantRequest, SubjectToken
from vinctor_service.v1_http import AgentIdentity, PepIdentity

POP_REPLAY_LOCK_ID = 0x56494E50


class PostgresLocalKeyRepository:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def create_workspace_key(
        self, *, workspace_id: str, raw_key: str | None = None,
        now: datetime | None = None, key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(WORKSPACE_KEY_PREFIX)
        _validate_prefix(key, WORKSPACE_KEY_PREFIX)
        return CreatedLocalKey(
            raw_key=key,
            record=self._create_key(
                key_type="workspace", workspace_id=workspace_id, agent_id=None,
                raw_key=key, now=now, key_id=key_id,
            ),
        )

    def create_agent_key(
        self, *, workspace_id: str, agent_id: str, raw_key: str | None = None,
        now: datetime | None = None, key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(AGENT_KEY_PREFIX)
        _validate_prefix(key, AGENT_KEY_PREFIX)
        return CreatedLocalKey(
            raw_key=key,
            record=self._create_key(
                key_type="agent", workspace_id=workspace_id, agent_id=agent_id,
                raw_key=key, now=now, key_id=key_id,
            ),
        )

    def create_pep_key(
        self, *, workspace_id: str, pep_id: str, raw_key: str | None = None,
        now: datetime | None = None, key_id: str | None = None,
    ) -> CreatedLocalKey:
        key = raw_key or _new_key(PEP_KEY_PREFIX)
        _validate_prefix(key, PEP_KEY_PREFIX)
        return CreatedLocalKey(
            raw_key=key,
            record=self._create_key(
                key_type="resource_server", workspace_id=workspace_id, agent_id=pep_id,
                raw_key=key, now=now, key_id=key_id,
            ),
        )

    def ensure_workspace_key(
        self, *, workspace_id: str, raw_key: str, now: datetime | None = None,
    ) -> LocalKeyRecord:
        return self._ensure_key(
            key_type="workspace", workspace_id=workspace_id, agent_id=None,
            raw_key=raw_key, expected_prefix=WORKSPACE_KEY_PREFIX, now=now,
        )

    def ensure_agent_key(
        self, *, workspace_id: str, agent_id: str, raw_key: str,
        now: datetime | None = None,
    ) -> LocalKeyRecord:
        return self._ensure_key(
            key_type="agent", workspace_id=workspace_id, agent_id=agent_id,
            raw_key=raw_key, expected_prefix=AGENT_KEY_PREFIX, now=now,
        )

    def ensure_pep_key(
        self, *, workspace_id: str, pep_id: str, raw_key: str,
        now: datetime | None = None,
    ) -> LocalKeyRecord:
        return self._ensure_key(
            key_type="resource_server", workspace_id=workspace_id, agent_id=pep_id,
            raw_key=raw_key, expected_prefix=PEP_KEY_PREFIX, now=now,
        )

    def _ensure_key(
        self, *, key_type: KeyType, workspace_id: str, agent_id: str | None,
        raw_key: str, expected_prefix: str, now: datetime | None,
    ) -> LocalKeyRecord:
        _validate_prefix(raw_key, expected_prefix)
        existing = self.get_by_raw_key(raw_key, touch=False)
        if existing is not None:
            _require_compatible(
                existing, key_type=key_type, workspace_id=workspace_id,
                agent_id=agent_id,
            )
            return existing
        return self._create_key(
            key_type=key_type, workspace_id=workspace_id, agent_id=agent_id,
            raw_key=raw_key, now=now, key_id=None,
        )

    def get_by_raw_key(
        self, raw_key: str, *, now: datetime | None = None, touch: bool = True,
    ) -> LocalKeyRecord | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT key_id, key_type, workspace_id, agent_id, key_hash,
                       key_prefix, status, created_at, last_used_at, revoked_at
                FROM local_keys WHERE key_hash = %s
                """,
                (_hash_key(raw_key),),
            ).fetchone()
            record = _key_from_row(row)
            if record is None or not touch or record.status != "active":
                return record
            used_at = now or datetime.now(UTC)
            self._conn.execute(
                "UPDATE local_keys SET last_used_at = %s WHERE key_id = %s",
                (used_at, record.key_id),
            )
        return LocalKeyRecord(
            key_id=record.key_id, key_type=record.key_type,
            workspace_id=record.workspace_id, agent_id=record.agent_id,
            key_hash=record.key_hash, key_prefix=record.key_prefix,
            status=record.status, created_at=record.created_at,
            last_used_at=used_at, revoked_at=record.revoked_at,
        )

    def resolve_workspace_identity(
        self, raw_key: str, *, now: datetime | None = None,
    ) -> WorkspaceIdentity | None:
        record = self.get_by_raw_key(raw_key, now=now)
        if record is None or record.status != "active" or record.key_type != "workspace":
            return None
        return WorkspaceIdentity(workspace_id=record.workspace_id)

    def resolve_agent_identity(
        self, raw_key: str, *, now: datetime | None = None,
    ) -> AgentIdentity | None:
        record = self.get_by_raw_key(raw_key, now=now)
        if (
            record is None or record.status != "active" or record.key_type != "agent"
            or record.agent_id is None
        ):
            return None
        return AgentIdentity(workspace_id=record.workspace_id, agent_id=record.agent_id)

    def resolve_pep_identity(
        self, raw_key: str, *, now: datetime | None = None,
    ) -> PepIdentity | None:
        record = self.get_by_raw_key(raw_key, now=now)
        if (
            record is None or record.status != "active"
            or record.key_type != "resource_server" or record.agent_id is None
        ):
            return None
        return PepIdentity(workspace_id=record.workspace_id, pep_id=record.agent_id)

    def revoke_key(
        self, key_id: str, *, now: datetime | None = None,
    ) -> LocalKeyRecord | None:
        record = self.get_by_id(key_id)
        if record is None or record.status == "revoked":
            return record
        revoked_at = now or datetime.now(UTC)
        with self._conn.transaction():
            self._conn.execute(
                "UPDATE local_keys SET status = 'revoked', revoked_at = %s WHERE key_id = %s",
                (revoked_at, key_id),
            )
        return LocalKeyRecord(
            key_id=record.key_id, key_type=record.key_type,
            workspace_id=record.workspace_id, agent_id=record.agent_id,
            key_hash=record.key_hash, key_prefix=record.key_prefix,
            status="revoked", created_at=record.created_at,
            last_used_at=record.last_used_at, revoked_at=revoked_at,
        )

    def get_by_id(self, key_id: str) -> LocalKeyRecord | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT key_id, key_type, workspace_id, agent_id, key_hash,
                       key_prefix, status, created_at, last_used_at, revoked_at
                FROM local_keys WHERE key_id = %s
                """,
                (key_id,),
            ).fetchone()
        return _key_from_row(row)

    def list_for_workspace(self, workspace_id: str) -> tuple[LocalKeyRecord, ...]:
        with self._conn.transaction():
            rows = self._conn.execute(
                """
                SELECT key_id, key_type, workspace_id, agent_id, key_hash,
                       key_prefix, status, created_at, last_used_at, revoked_at
                FROM local_keys WHERE workspace_id = %s ORDER BY created_at, key_id
                """,
                (workspace_id,),
            ).fetchall()
        return tuple(record for row in rows if (record := _key_from_row(row)) is not None)

    def _create_key(
        self, *, key_type: KeyType, workspace_id: str, agent_id: str | None,
        raw_key: str, now: datetime | None, key_id: str | None,
    ) -> LocalKeyRecord:
        record = LocalKeyRecord(
            key_id=key_id or _new_key("lkey_"), key_type=key_type,
            workspace_id=workspace_id, agent_id=agent_id,
            key_hash=_hash_key(raw_key), key_prefix=_key_prefix(raw_key),
            status="active", created_at=now or datetime.now(UTC),
        )
        with self._conn.transaction():
            self._conn.execute(
                """
                INSERT INTO local_keys (
                    key_id, key_type, workspace_id, agent_id, key_hash,
                    key_prefix, status, created_at, last_used_at, revoked_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL)
                """,
                (
                    record.key_id, record.key_type, record.workspace_id,
                    record.agent_id, record.key_hash, record.key_prefix,
                    record.status, record.created_at,
                ),
            )
        return record


class PostgresGrantRequestRepository:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def insert_request(self, request: GrantRequest) -> None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                INSERT INTO grant_requests (
                    request_id, workspace_id, requester_agent_id, target_agent_id,
                    requested_scopes_json, requested_ttl_seconds, reason, status,
                    created_at, decided_at, decided_by, decision_reason,
                    issued_grant_ref, task_id, session_id, boundary_id,
                    requester_runtime, repo, worktree
                ) VALUES (
                    %s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                ) ON CONFLICT (request_id) DO NOTHING RETURNING request_id
                """,
                _grant_request_values(request),
            ).fetchone()
        if row is None:
            raise ValueError(f"duplicate grant request_id: {request.request_id}")

    def get_request(self, request_id: str) -> GrantRequest | None:
        with self._conn.transaction():
            row = self._conn.execute(
                f"{_GRANT_REQUEST_SELECT} WHERE request_id = %s", (request_id,)
            ).fetchone()
        return _grant_request_from_row(row)

    def list_requests_for_workspace(self, workspace_id: str) -> tuple[GrantRequest, ...]:
        with self._conn.transaction():
            rows = self._conn.execute(
                f"{_GRANT_REQUEST_SELECT} WHERE workspace_id = %s "
                "ORDER BY created_at, request_id",
                (workspace_id,),
            ).fetchall()
        return tuple(
            request for row in rows
            if (request := _grant_request_from_row(row)) is not None
        )

    def update_request(self, request: GrantRequest) -> None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                UPDATE grant_requests SET
                    workspace_id = %s, requester_agent_id = %s, target_agent_id = %s,
                    requested_scopes_json = %s::jsonb, requested_ttl_seconds = %s,
                    reason = %s, status = %s, created_at = %s, decided_at = %s,
                    decided_by = %s, decision_reason = %s, issued_grant_ref = %s,
                    task_id = %s, session_id = %s, boundary_id = %s,
                    requester_runtime = %s, repo = %s, worktree = %s
                WHERE request_id = %s RETURNING request_id
                """,
                (*_grant_request_values(request)[1:], request.request_id),
            ).fetchone()
        if row is None:
            raise ValueError(f"unknown grant request_id: {request.request_id}")


class PostgresSubjectTokenRepository:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def insert(self, token: SubjectToken) -> None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                INSERT INTO subject_tokens (
                    token_id, token_hash, workspace_id, agent_id, grant_ref,
                    audience, issued_at, expires_at, created_by, revoked_at,
                    bound_action, bound_resource, pop_secret
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (token_hash) DO NOTHING RETURNING token_id
                """,
                _subject_token_values(token),
            ).fetchone()
        if row is None:
            raise ValueError(f"duplicate subject token_hash: {token.token_hash}")

    def get_by_hash(self, token_hash: str) -> SubjectToken | None:
        with self._conn.transaction():
            row = self._conn.execute(
                f"{_SUBJECT_TOKEN_SELECT}, pop_secret FROM subject_tokens "
                "WHERE token_hash = %s",
                (token_hash,),
            ).fetchone()
        return _subject_token_from_row(row)

    def get_by_id(self, token_id: str) -> SubjectToken | None:
        with self._conn.transaction():
            row = self._conn.execute(
                f"{_SUBJECT_TOKEN_SELECT} FROM subject_tokens WHERE token_id = %s",
                (token_id,),
            ).fetchone()
        return _subject_token_from_row(row)

    def revoke(self, token_id: str, *, now: datetime) -> bool:
        with self._conn.transaction():
            row = self._conn.execute(
                "UPDATE subject_tokens SET revoked_at = %s WHERE token_id = %s "
                "RETURNING token_id",
                (now, token_id),
            ).fetchone()
        return row is not None

    def list_subject_tokens(self, workspace_id: str) -> tuple[SubjectToken, ...]:
        with self._conn.transaction():
            rows = self._conn.execute(
                f"{_SUBJECT_TOKEN_SELECT} FROM subject_tokens "
                "WHERE workspace_id = %s ORDER BY issued_at",
                (workspace_id,),
            ).fetchall()
        return tuple(
            token for row in rows if (token := _subject_token_from_row(row)) is not None
        )


class PostgresReplayStore:
    def __init__(self, conn: Any, max_entries: int = 10000, max_per_token: int = 256) -> None:
        self._conn = conn
        self._max = max_entries
        self._max_per_token = max_per_token

    def check_and_record(
        self, *, token_id: str, nonce: str, ts: int, now_unix: int, skew: int,
    ) -> bool:
        cutoff = now_unix - skew
        with self._conn.transaction():
            self._conn.execute("SELECT pg_advisory_xact_lock(%s)", (POP_REPLAY_LOCK_ID,))
            self._conn.execute("DELETE FROM pop_replay_nonces WHERE ts < %s", (cutoff,))
            if self._conn.execute(
                "SELECT 1 FROM pop_replay_nonces WHERE token_id = %s AND nonce = %s",
                (token_id, nonce),
            ).fetchone() is not None:
                return False
            per_token = self._conn.execute(
                "SELECT COUNT(*) FROM pop_replay_nonces WHERE token_id = %s",
                (token_id,),
            ).fetchone()[0]
            if per_token >= self._max_per_token:
                self._conn.execute(
                    """
                    DELETE FROM pop_replay_nonces
                    WHERE (token_id, nonce) = (
                        SELECT token_id, nonce FROM pop_replay_nonces
                        WHERE token_id = %s ORDER BY ts, nonce LIMIT 1
                    )
                    """,
                    (token_id,),
                )
            elif self._conn.execute(
                "SELECT COUNT(*) FROM pop_replay_nonces"
            ).fetchone()[0] >= self._max:
                return False
            return self._conn.execute(
                """
                INSERT INTO pop_replay_nonces (token_id, nonce, ts)
                VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING nonce
                """,
                (token_id, nonce, ts),
            ).fetchone() is not None


_GRANT_REQUEST_SELECT = """
SELECT request_id, workspace_id, requester_agent_id, target_agent_id,
       requested_scopes_json, requested_ttl_seconds, reason, status,
       created_at, decided_at, decided_by, decision_reason, issued_grant_ref,
       task_id, session_id, boundary_id, requester_runtime, repo, worktree
FROM grant_requests
""".strip()

_SUBJECT_TOKEN_SELECT = """
SELECT token_id, token_hash, workspace_id, agent_id, grant_ref, audience,
       issued_at, expires_at, created_by, revoked_at, bound_action, bound_resource
""".strip()


def _grant_request_values(request: GrantRequest) -> tuple[object, ...]:
    return (
        request.request_id, request.workspace_id, request.requester_agent_id,
        request.target_agent_id, json.dumps(list(request.requested_scopes)),
        request.requested_ttl_seconds, request.reason, request.status,
        request.created_at, request.decided_at, request.decided_by,
        request.decision_reason, request.issued_grant_ref, request.task_id,
        request.session_id, request.boundary_id, request.requester_runtime,
        request.repo, request.worktree,
    )


def _grant_request_from_row(row: Any) -> GrantRequest | None:
    if row is None:
        return None
    scopes = json.loads(row[4]) if isinstance(row[4], str) else row[4]
    return GrantRequest(
        request_id=row[0], workspace_id=row[1], requester_agent_id=row[2],
        target_agent_id=row[3], requested_scopes=tuple(scopes),
        requested_ttl_seconds=row[5], reason=row[6], status=row[7],
        created_at=_aware(row[8]), decided_at=_aware(row[9]), decided_by=row[10],
        decision_reason=row[11], issued_grant_ref=row[12], task_id=row[13],
        session_id=row[14], boundary_id=row[15], requester_runtime=row[16],
        repo=row[17], worktree=row[18],
    )


def _subject_token_values(token: SubjectToken) -> tuple[object, ...]:
    return (
        token.token_id, token.token_hash, token.workspace_id, token.agent_id,
        token.grant_ref, token.audience, token.issued_at, token.expires_at,
        token.created_by, token.revoked_at, token.bound_action,
        token.bound_resource, token.pop_secret,
    )


def _subject_token_from_row(row: Any) -> SubjectToken | None:
    if row is None:
        return None
    return SubjectToken(
        token_id=row[0], token_hash=row[1], workspace_id=row[2], agent_id=row[3],
        grant_ref=row[4], audience=row[5], issued_at=_aware(row[6]),
        expires_at=_aware(row[7]), created_by=row[8], revoked_at=_aware(row[9]),
        bound_action=row[10], bound_resource=row[11],
        pop_secret=row[12] if len(row) > 12 else None,
    )


def _key_from_row(row: Any) -> LocalKeyRecord | None:
    if row is None:
        return None
    return LocalKeyRecord(
        key_id=row[0], key_type=row[1], workspace_id=row[2], agent_id=row[3],
        key_hash=row[4], key_prefix=row[5], status=row[6],
        created_at=_aware(row[7]), last_used_at=_aware(row[8]),
        revoked_at=_aware(row[9]),
    )


def _aware(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


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
    record: LocalKeyRecord, *, key_type: KeyType, workspace_id: str,
    agent_id: str | None,
) -> None:
    if record.status != "active":
        raise ValueError("key is revoked")
    if (
        record.key_type != key_type or record.workspace_id != workspace_id
        or record.agent_id != agent_id
    ):
        raise ValueError("key has incompatible identity")
