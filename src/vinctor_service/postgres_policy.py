from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from vinctor_service.policy_files import (
    PolicyRollbackResult,
    PolicyVersionInfo,
    _validated_policy_snapshot,
)

POLICY_VERSION_LOCK_ID = 0x56504F4C


def record_postgres_policy_version(
    *,
    service: Any,
    workspace_id: str,
    action: str,
    source_version: int | None,
    applied_by: str,
    now: datetime,
) -> int:
    with service.conn.transaction():
        return _insert_version(
            service=service,
            workspace_id=workspace_id,
            action=action,
            source_version=source_version,
            applied_by=applied_by,
            now=now,
        )


def list_postgres_policy_versions(
    *, service: Any, workspace_id: str
) -> tuple[PolicyVersionInfo, ...]:
    with service.conn.transaction():
        rows = service.conn.execute(
            """
            SELECT workspace_id, version, action, source_version, applied_by, created_at
            FROM policy_versions
            WHERE workspace_id = %s
            ORDER BY version
            """,
            (workspace_id,),
        ).fetchall()
    return tuple(
        PolicyVersionInfo(
            workspace_id=row[0],
            version=row[1],
            action=row[2],
            source_version=row[3],
            applied_by=row[4],
            created_at=row[5],
        )
        for row in rows
    )


def rollback_postgres_policy_version(
    *,
    service: Any,
    workspace_id: str,
    version: int,
    applied_by: str,
    now: datetime,
) -> PolicyRollbackResult:
    with service.conn.transaction():
        row = service.conn.execute(
            """
            SELECT snapshot_json FROM policy_versions
            WHERE workspace_id = %s AND version = %s
            """,
            (workspace_id, version),
        ).fetchone()
        if row is None:
            raise ValueError(f"unknown policy version: {version}")
        raw_snapshot = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        snapshot = _validated_policy_snapshot(raw_snapshot)
        _restore_snapshot(
            service=service,
            workspace_id=workspace_id,
            snapshot=snapshot,
            now=now,
        )
        new_version = _insert_version(
            service=service,
            workspace_id=workspace_id,
            action="rollback",
            source_version=version,
            applied_by=applied_by,
            now=now,
        )
    return PolicyRollbackResult(
        workspace_id=workspace_id,
        restored_version=version,
        policy_version=new_version,
    )


def _insert_version(
    *,
    service: Any,
    workspace_id: str,
    action: str,
    source_version: int | None,
    applied_by: str,
    now: datetime,
) -> int:
    service.conn.execute("SELECT pg_advisory_xact_lock(%s)", (POLICY_VERSION_LOCK_ID,))
    row = service.conn.execute(
        "SELECT COALESCE(MAX(version), 0) FROM policy_versions WHERE workspace_id = %s",
        (workspace_id,),
    ).fetchone()
    version = int(row[0]) + 1
    snapshot = _snapshot_state(service=service, workspace_id=workspace_id)
    service.conn.execute(
        """
        INSERT INTO policy_versions (
            workspace_id, version, action, source_version,
            snapshot_json, applied_by, created_at
        ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s)
        """,
        (
            workspace_id,
            version,
            action,
            source_version,
            json.dumps(snapshot, sort_keys=True),
            applied_by,
            now,
        ),
    )
    return version


def _snapshot_state(*, service: Any, workspace_id: str) -> dict[str, object]:
    bounds = service.conn.execute(
        """
        SELECT agent_id, scopes_json, max_ttl_seconds, updated_at
        FROM agent_issuable_scope_bounds
        WHERE workspace_id = %s
        ORDER BY agent_id
        """,
        (workspace_id,),
    ).fetchall()
    rules = service.conn.execute(
        """
        SELECT rule_id, name, target_agent_id, allowed_scopes_json,
               max_ttl_seconds, status, created_by, created_at,
               updated_by, updated_at
        FROM auto_approval_rules
        WHERE workspace_id = %s
        ORDER BY created_at, rule_id
        """,
        (workspace_id,),
    ).fetchall()
    settings = service.conn.execute(
        """
        SELECT agent_id, require_boundary, updated_at
        FROM agent_enforcement_settings
        WHERE workspace_id = %s AND require_boundary_set
        ORDER BY agent_id
        """,
        (workspace_id,),
    ).fetchall()
    return {
        "version": 1,
        "agent_bounds": [
            {
                "agent_id": row[0],
                "scopes": _json_value(row[1]),
                "max_ttl_seconds": row[2],
                "updated_at": row[3].isoformat(),
            }
            for row in bounds
        ],
        "auto_approval_rules": [
            {
                "rule_id": row[0],
                "name": row[1],
                "target_agent_id": row[2],
                "allowed_scopes": _json_value(row[3]),
                "max_ttl_seconds": row[4],
                "status": row[5],
                "created_by": row[6],
                "created_at": row[7].isoformat(),
                "updated_by": row[8],
                "updated_at": row[9].isoformat() if row[9] is not None else None,
            }
            for row in rules
        ],
        "require_boundary_settings": [
            {
                "agent_id": row[0],
                "require_boundary": row[1],
                "updated_at": row[2].isoformat(),
            }
            for row in settings
        ],
    }


def _restore_snapshot(
    *,
    service: Any,
    workspace_id: str,
    snapshot: dict[str, Any],
    now: datetime,
) -> None:
    conn = service.conn
    conn.execute(
        "DELETE FROM agent_issuable_scope_bounds WHERE workspace_id = %s",
        (workspace_id,),
    )
    for entry in snapshot["agent_bounds"]:
        conn.execute(
            """
            INSERT INTO agent_issuable_scope_bounds (
                workspace_id, agent_id, scopes_json, max_ttl_seconds, updated_at
            ) VALUES (%s, %s, %s::jsonb, %s, %s)
            """,
            (
                workspace_id,
                entry["agent_id"],
                json.dumps(entry["scopes"]),
                entry["max_ttl_seconds"],
                entry["updated_at"],
            ),
        )

    conn.execute("DELETE FROM auto_approval_rules WHERE workspace_id = %s", (workspace_id,))
    for entry in snapshot["auto_approval_rules"]:
        conn.execute(
            """
            INSERT INTO auto_approval_rules (
                rule_id, workspace_id, name, target_agent_id,
                allowed_scopes_json, max_ttl_seconds, status,
                created_by, created_at, updated_by, updated_at
            ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s)
            """,
            (
                entry["rule_id"],
                workspace_id,
                entry["name"],
                entry["target_agent_id"],
                json.dumps(entry["allowed_scopes"]),
                entry["max_ttl_seconds"],
                entry["status"],
                entry["created_by"],
                entry["created_at"],
                entry["updated_by"],
                entry["updated_at"],
            ),
        )

    conn.execute(
        """
        UPDATE agent_enforcement_settings
        SET require_boundary_set = FALSE, updated_at = %s
        WHERE workspace_id = %s
        """,
        (now, workspace_id),
    )
    conn.execute(
        """
        DELETE FROM agent_enforcement_settings
        WHERE workspace_id = %s AND NOT require_boundary_set
          AND NOT require_subject_token AND NOT require_pop
        """,
        (workspace_id,),
    )
    for entry in snapshot["require_boundary_settings"]:
        conn.execute(
            """
            INSERT INTO agent_enforcement_settings (
                workspace_id, agent_id, require_boundary,
                require_boundary_set, updated_at
            ) VALUES (%s, %s, %s, TRUE, %s)
            ON CONFLICT (workspace_id, agent_id) DO UPDATE SET
                require_boundary = EXCLUDED.require_boundary,
                require_boundary_set = TRUE,
                updated_at = EXCLUDED.updated_at
            """,
            (workspace_id, entry["agent_id"], entry["require_boundary"], now),
        )


def _json_value(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value
