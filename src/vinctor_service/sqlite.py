from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from vinctor_core.models import AuditEvent, Grant


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


def _datetime_to_storage(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _datetime_from_storage(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None
