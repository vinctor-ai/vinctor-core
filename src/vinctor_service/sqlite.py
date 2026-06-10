from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime

from vinctor_core import (
    disable_boundary,
    enable_boundary,
    get_boundary_for_workspace,
    register_boundary,
)
from vinctor_core.models import AuditEvent, Boundary, BoundaryRegistrationInput, Grant
from vinctor_service.models import V1EnforceRequest, V1EnforceResponse
from vinctor_service.v1_enforce import enforce_v1_contract


def init_sqlite_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS grants (
            grant_id TEXT PRIMARY KEY,
            grant_ref TEXT NOT NULL UNIQUE,
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            status TEXT NOT NULL,
            expires_at TEXT
        );

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
            created_at TEXT NOT NULL,
            event_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS boundaries (
            boundary_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            name TEXT NOT NULL,
            runtime TEXT NOT NULL,
            boundary_type TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(workspace_id, name)
        );
        """
    )
    conn.commit()


def insert_grant(conn: sqlite3.Connection, grant: Grant) -> None:
    existing = conn.execute(
        "SELECT 1 FROM grants WHERE grant_ref = ?",
        (grant.grant_ref,),
    ).fetchone()
    if existing is not None:
        raise ValueError(f"duplicate grant_ref: {grant.grant_ref}")

    with conn:
        conn.execute(
            """
            INSERT INTO grants (
                grant_id, grant_ref, workspace_id, agent_id,
                scopes_json, status, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                grant.grant_id,
                grant.grant_ref,
                grant.workspace_id,
                grant.agent_id,
                json.dumps(list(grant.scopes)),
                grant.status,
                _datetime_to_storage(grant.expires_at),
            ),
        )


class SQLiteGrantRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def get_by_ref(self, grant_ref: str) -> Grant | None:
        row = self._conn.execute(
            """
            SELECT grant_id, grant_ref, workspace_id, agent_id,
                   scopes_json, status, expires_at
            FROM grants
            WHERE grant_ref = ?
            """,
            (grant_ref,),
        ).fetchone()
        if row is None:
            return None

        scopes = tuple(json.loads(row[4]))
        return Grant(
            grant_id=row[0],
            grant_ref=row[1],
            workspace_id=row[2],
            agent_id=row[3],
            scopes=scopes,
            status=row[5],
            expires_at=_datetime_from_storage(row[6]),
        )


class SQLiteAuditWriter:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def write(self, event: AuditEvent) -> None:
        event_data = event.to_dict()
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, event_type, decision, reason,
                    workspace_id, agent_id, grant_id, grant_ref,
                    action, resource, scope_attempted, scope_matched,
                    boundary_id, runtime, boundary_type, created_at, event_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event.created_at.isoformat(),
                    json.dumps(event_data, sort_keys=True),
                ),
            )

    def get(self, event_id: str) -> AuditEvent | None:
        row = self._conn.execute(
            """
            SELECT event_json
            FROM audit_events
            WHERE event_id = ?
            """,
            (event_id,),
        ).fetchone()
        return _audit_event_from_json(row[0]) if row is not None else None

    def list_all(self) -> list[AuditEvent]:
        rows = self._conn.execute(
            """
            SELECT event_json
            FROM audit_events
            ORDER BY rowid
            """
        ).fetchall()
        return [_audit_event_from_json(row[0]) for row in rows]


class SQLiteBoundaryRegistry:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def add(self, boundary: Boundary) -> Boundary:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO boundaries (
                    boundary_id, workspace_id, name, runtime, boundary_type,
                    mode, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(boundary_id) DO UPDATE SET
                    workspace_id = excluded.workspace_id,
                    name = excluded.name,
                    runtime = excluded.runtime,
                    boundary_type = excluded.boundary_type,
                    mode = excluded.mode,
                    status = excluded.status,
                    created_at = excluded.created_at,
                    updated_at = excluded.updated_at
                """,
                (
                    boundary.boundary_id,
                    boundary.workspace_id,
                    boundary.name,
                    boundary.runtime,
                    boundary.boundary_type,
                    boundary.mode,
                    boundary.status,
                    boundary.created_at.isoformat(),
                    boundary.updated_at.isoformat(),
                ),
            )
        return boundary

    def get(self, boundary_id: str) -> Boundary | None:
        row = self._conn.execute(
            """
            SELECT boundary_id, workspace_id, name, runtime, boundary_type,
                   mode, status, created_at, updated_at
            FROM boundaries
            WHERE boundary_id = ?
            """,
            (boundary_id,),
        ).fetchone()
        return _boundary_from_row(row)

    def list_for_workspace(self, workspace_id: str) -> list[Boundary]:
        rows = self._conn.execute(
            """
            SELECT boundary_id, workspace_id, name, runtime, boundary_type,
                   mode, status, created_at, updated_at
            FROM boundaries
            WHERE workspace_id = ?
            ORDER BY created_at, boundary_id
            """,
            (workspace_id,),
        ).fetchall()
        return [
            boundary
            for row in rows
            if (boundary := _boundary_from_row(row)) is not None
        ]


@dataclass
class SQLiteV1Service:
    conn: sqlite3.Connection
    initialize_schema: bool = True
    grant_repository: SQLiteGrantRepository = field(init=False)
    audit_writer: SQLiteAuditWriter = field(init=False)
    boundary_registry: SQLiteBoundaryRegistry = field(init=False)

    def __post_init__(self) -> None:
        if self.initialize_schema:
            init_sqlite_schema(self.conn)
        self.grant_repository = SQLiteGrantRepository(self.conn)
        self.audit_writer = SQLiteAuditWriter(self.conn)
        self.boundary_registry = SQLiteBoundaryRegistry(self.conn)

    def insert_grant(self, grant: Grant) -> None:
        insert_grant(self.conn, grant)

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self.audit_writer.list_all())

    def get_audit_event(self, event_id: str) -> AuditEvent | None:
        return self.audit_writer.get(event_id)

    def register_boundary(
        self,
        registration: BoundaryRegistrationInput,
        *,
        now: datetime | None = None,
        boundary_id: str | None = None,
    ) -> Boundary:
        return register_boundary(
            self.boundary_registry,
            registration,
            now=now,
            boundary_id=boundary_id,
        )

    def disable_boundary(
        self,
        *,
        boundary_id: str,
        workspace_id: str,
        now: datetime | None = None,
    ) -> Boundary | None:
        return disable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
        )

    def enable_boundary(
        self,
        *,
        boundary_id: str,
        workspace_id: str,
        now: datetime | None = None,
    ) -> Boundary | None:
        return enable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
        )

    def list_boundaries(self, workspace_id: str) -> tuple[Boundary, ...]:
        return tuple(self.boundary_registry.list_for_workspace(workspace_id))

    def get_boundary(self, *, boundary_id: str, workspace_id: str) -> Boundary | None:
        return get_boundary_for_workspace(
            self.boundary_registry,
            boundary_id,
            workspace_id,
        )

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
        )


def _datetime_to_storage(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _datetime_from_storage(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def _boundary_from_row(row: sqlite3.Row | tuple | None) -> Boundary | None:
    if row is None:
        return None
    return Boundary(
        boundary_id=row[0],
        workspace_id=row[1],
        name=row[2],
        runtime=row[3],
        boundary_type=row[4],
        mode=row[5],
        status=row[6],
        created_at=datetime.fromisoformat(row[7]),
        updated_at=datetime.fromisoformat(row[8]),
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
    )
