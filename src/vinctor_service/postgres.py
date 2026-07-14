from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from typing import Any

from vinctor_core.models import AuditEvent, Grant
from vinctor_service.audit import AuthFailureAuditThrottle
from vinctor_service.audit_anchor import AuditAnchor, NullAnchor
from vinctor_service.audit_chain import GENESIS_PREV_HASH, row_hash
from vinctor_service.models import (
    V1EnforceRequest,
    V1EnforceResponse,
    V1ObserveRequest,
    V1ObserveResponse,
)
from vinctor_service.observations import record_observation
from vinctor_service.v1_enforce import enforce_v1_contract

AUDIT_CHAIN_LOCK_ID = 0x56494E43


def connect_postgres(dsn: str):
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError(
            "Postgres support requires `pip install vinctor-core[postgres]`"
        ) from exc
    return psycopg.connect(dsn)


def init_postgres_schema(conn: Any) -> None:
    statements = (
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS grants (
            grant_id TEXT PRIMARY KEY,
            grant_ref TEXT NOT NULL UNIQUE,
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            scopes_json JSONB NOT NULL,
            status TEXT NOT NULL,
            expires_at TIMESTAMPTZ
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_grants_workspace
        ON grants(workspace_id, agent_id, status)
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            decision TEXT NOT NULL,
            reason TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            grant_id TEXT NOT NULL,
            grant_ref TEXT NOT NULL,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            scope_attempted TEXT NOT NULL,
            scope_matched TEXT,
            boundary_id TEXT,
            runtime TEXT,
            boundary_type TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            enforcing_principal TEXT,
            reason_code TEXT,
            occurrence_count INTEGER,
            first_seen_at TIMESTAMPTZ,
            last_seen_at TIMESTAMPTZ,
            identity_proven BOOLEAN NOT NULL DEFAULT FALSE,
            token_id TEXT,
            event_json TEXT NOT NULL,
            seq BIGINT NOT NULL UNIQUE,
            prev_hash TEXT NOT NULL,
            row_hash TEXT NOT NULL
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_audit_workspace_seq
        ON audit_events(workspace_id, seq DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_audit_agent
        ON audit_events(workspace_id, agent_id, seq DESC)
        """,
    )
    with conn.transaction():
        for statement in statements:
            conn.execute(statement)
        conn.execute(
            """
            INSERT INTO schema_migrations (version, applied_at)
            VALUES (%s, %s)
            ON CONFLICT (version) DO NOTHING
            """,
            (1, datetime.now(UTC)),
        )


class PostgresGrantRepository:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def get_by_ref(self, grant_ref: str) -> Grant | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT grant_id, grant_ref, workspace_id, agent_id,
                       scopes_json, status, expires_at
                FROM grants
                WHERE grant_ref = %s
                """,
                (grant_ref,),
            ).fetchone()
        return _grant_from_row(row)

    def list_grants_for_workspace(
        self,
        workspace_id: str,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]:
        clauses = ["workspace_id = %s"]
        params: list[object] = [workspace_id]
        if agent_id is not None:
            clauses.append("agent_id = %s")
            params.append(agent_id)
        if status is not None:
            clauses.append("status = %s")
            params.append(status)
        with self._conn.transaction():
            rows = self._conn.execute(
                f"""
                SELECT grant_id, grant_ref, workspace_id, agent_id,
                       scopes_json, status, expires_at
                FROM grants
                WHERE {' AND '.join(clauses)}
                ORDER BY grant_id
                """,
                tuple(params),
            ).fetchall()
        return tuple(grant for row in rows if (grant := _grant_from_row(row)) is not None)

    def insert(self, grant: Grant) -> None:
        with self._conn.transaction():
            self._conn.execute(
                """
                INSERT INTO grants (
                    grant_id, grant_ref, workspace_id, agent_id,
                    scopes_json, status, expires_at
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)
                """,
                (
                    grant.grant_id,
                    grant.grant_ref,
                    grant.workspace_id,
                    grant.agent_id,
                    json.dumps(list(grant.scopes)),
                    grant.status,
                    grant.expires_at,
                ),
            )

    def revoke(self, *, grant_ref: str, workspace_id: str) -> Grant | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                UPDATE grants
                SET status = 'revoked'
                WHERE grant_ref = %s AND workspace_id = %s
                RETURNING grant_id, grant_ref, workspace_id, agent_id,
                          scopes_json, status, expires_at
                """,
                (grant_ref, workspace_id),
            ).fetchone()
        return _grant_from_row(row)


class PostgresAuditWriter:
    def __init__(self, conn: Any, anchor: AuditAnchor | None = None) -> None:
        self._conn = conn
        self._anchor = anchor if anchor is not None else NullAnchor()

    def write(self, event: AuditEvent) -> None:
        event_json = json.dumps(event.to_dict(), sort_keys=True)
        with self._conn.transaction():
            self._conn.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_CHAIN_LOCK_ID,))
            head = self._conn.execute(
                "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            previous_seq = head[0] if head else 0
            previous_hash = head[1] if head else GENESIS_PREV_HASH
            seq = previous_seq + 1
            current_hash = row_hash(seq, event_json, previous_hash)
            self._conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, event_type, decision, reason,
                    workspace_id, agent_id, grant_id, grant_ref,
                    action, resource, scope_attempted, scope_matched,
                    boundary_id, runtime, boundary_type, created_at,
                    enforcing_principal, reason_code, occurrence_count,
                    first_seen_at, last_seen_at, identity_proven, token_id,
                    event_json, seq, prev_hash, row_hash
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    event.event_id,
                    event.event_type,
                    event.decision,
                    event.reason,
                    event.workspace_id,
                    event.agent_id,
                    event.grant_id,
                    event.grant_ref,
                    event.action,
                    event.resource,
                    event.scope_attempted,
                    event.scope_matched,
                    event.boundary_id,
                    event.runtime,
                    event.boundary_type,
                    event.created_at,
                    event.enforcing_principal,
                    event.reason_code,
                    event.occurrence_count,
                    event.first_seen_at,
                    event.last_seen_at,
                    event.identity_proven,
                    event.token_id,
                    event_json,
                    seq,
                    previous_hash,
                    current_hash,
                ),
            )
        try:
            self._anchor.emit(seq, current_hash, event.created_at.isoformat())
        except Exception as exc:  # noqa: BLE001 - anchor is deliberately fail-open
            sys.stderr.write(f"vinctor: audit anchor emit raised: {exc}\n")

    def get(self, event_id: str) -> AuditEvent | None:
        with self._conn.transaction():
            row = self._conn.execute(
                "SELECT event_json FROM audit_events WHERE event_id = %s",
                (event_id,),
            ).fetchone()
        return _audit_event_from_json(row[0]) if row is not None else None

    def list_all(self) -> list[AuditEvent]:
        with self._conn.transaction():
            rows = self._conn.execute(
                "SELECT event_json FROM audit_events ORDER BY seq"
            ).fetchall()
        return [_audit_event_from_json(row[0]) for row in rows]

    def list_filtered(
        self,
        workspace_id: str,
        *,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        agent_id: str | None = None,
        request_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        identity_proven: bool | None = None,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        clauses = ["workspace_id = %s"]
        params: list[object] = [workspace_id]
        filters = (
            ("event_type", event_type),
            ("grant_ref", grant_ref),
            ("boundary_id", boundary_id),
            ("agent_id", agent_id),
            ("reason_code", reason_code),
            ("enforcing_principal", enforcing_principal),
            ("identity_proven", identity_proven),
        )
        for column, value in filters:
            if value is not None:
                clauses.append(f"{column} = %s")
                params.append(value)
        if request_id is not None:
            clauses.append("(resource = %s OR grant_ref = %s)")
            params.extend((f"grant_request/{request_id}", request_id))
        query = (
            "SELECT event_json FROM audit_events "
            f"WHERE {' AND '.join(clauses)} ORDER BY seq DESC"
        )
        if limit is not None:
            query += " LIMIT %s"
            params.append(limit)
        with self._conn.transaction():
            rows = self._conn.execute(query, tuple(params)).fetchall()
        return tuple(_audit_event_from_json(row[0]) for row in reversed(rows))


class PostgresV1Service:
    def __init__(self, conn: Any, *, initialize_schema: bool = True) -> None:
        self.conn = conn
        if initialize_schema:
            init_postgres_schema(conn)
        self.grant_repository = PostgresGrantRepository(conn)
        self.audit_writer = PostgresAuditWriter(conn)
        self._auth_failures = AuthFailureAuditThrottle()

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self.audit_writer.list_all())

    def get_audit_event(self, event_id: str) -> AuditEvent | None:
        return self.audit_writer.get(event_id)

    def list_filtered(self, workspace_id: str, **filters: Any) -> tuple[AuditEvent, ...]:
        return self.audit_writer.list_filtered(workspace_id, **filters)

    def insert_grant(self, grant: Grant) -> None:
        self.grant_repository.insert(grant)

    def record_auth_failure(
        self, *, surface: str, boundary_id: str | None, now: datetime
    ) -> None:
        self._auth_failures.record(
            self.audit_writer,
            surface=surface,
            boundary_id=boundary_id,
            now=now,
        )

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
        )

    def observe(self, request: V1ObserveRequest, *, now: datetime) -> V1ObserveResponse:
        return record_observation(request, audit_writer=self.audit_writer, now=now)


def _grant_from_row(row: Any) -> Grant | None:
    if row is None:
        return None
    scopes = json.loads(row[4]) if isinstance(row[4], str) else row[4]
    expires_at = row[6]
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return Grant(
        grant_id=row[0],
        grant_ref=row[1],
        workspace_id=row[2],
        agent_id=row[3],
        scopes=tuple(scopes),
        status=row[5],
        expires_at=expires_at,
    )


def _audit_event_from_json(value: str) -> AuditEvent:
    data = json.loads(value)
    return AuditEvent(
        event_id=data["event_id"],
        event_type=data["event_type"],
        decision=data["decision"],
        reason=data["reason"],
        workspace_id=data["workspace_id"],
        agent_id=data["agent_id"],
        grant_id=data["grant_id"],
        grant_ref=data["grant_ref"],
        action=data["action"],
        resource=data["resource"],
        scope_attempted=data["scope_attempted"],
        scope_matched=data["scope_matched"],
        boundary_id=data["boundary_id"],
        runtime=data["runtime"],
        boundary_type=data["boundary_type"],
        created_at=datetime.fromisoformat(data["created_at"]),
        enforcing_principal=data.get("enforcing_principal"),
        reason_code=data.get("reason_code"),
        occurrence_count=data.get("occurrence_count"),
        first_seen_at=_optional_datetime(data.get("first_seen_at")),
        last_seen_at=_optional_datetime(data.get("last_seen_at")),
        identity_proven=data.get("identity_proven", False),
        token_id=data.get("token_id"),
    )


def _optional_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None
