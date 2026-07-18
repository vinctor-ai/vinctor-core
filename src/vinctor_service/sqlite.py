from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from vinctor_core import (
    disable_boundary,
    enable_boundary,
    get_boundary_for_workspace,
    register_boundary,
)
from vinctor_core.audit import (
    EVENT_AUTO_APPROVAL_RULE_CREATED,
    EVENT_AUTO_APPROVAL_RULE_DISABLED,
    EVENT_BOUNDARY_REGISTERED,
    EVENT_BOUNDARY_STATUS_CHANGED,
    EVENT_ENFORCEMENT_SETTING_CHANGED,
    EVENT_SCOPE_BOUNDS_SET,
)
from vinctor_core.models import AuditEvent, Boundary, BoundaryRegistrationInput, Grant
from vinctor_service.audit import AuthFailureAuditThrottle
from vinctor_service.audit_anchor import AuditAnchor, NullAnchor, anchor_from_env
from vinctor_service.audit_chain import (
    GENESIS_PREV_HASH,
    AnchorRecord,
    AnchorVerification,
    ChainVerification,
    crosscheck_values_match,
    event_json_value,
    row_hash,
    subject_token_verified_from_json,
)
from vinctor_service.audit_export import (
    AuditExport,
    ExportingAuditWriter,
    NullExport,
    audit_export_from_env,
)
from vinctor_service.auto_approval import (
    auto_approve_grant_request,
    create_auto_approval_rule,
    disable_auto_approval_rule,
    evaluate_auto_approval,
    list_auto_approval_rules,
)
from vinctor_service.control_audit import ControlPlaneAuditor
from vinctor_service.grant_requests import (
    approve_grant_request,
    create_grant_request,
    list_grant_requests,
    lookup_grant_request,
    reject_grant_request,
)
from vinctor_service.grants import (
    ScopeBoundsListing,
    issue_grant,
    list_grants,
    lookup_grant,
    revoke_grant,
    validate_issuable_scope_bounds,
)
from vinctor_service.models import (
    AgentIssuableBounds,
    AutoApprovalEvaluationResult,
    AutoApprovalRule,
    GrantIssueRequest,
    GrantIssueResult,
    GrantRequest,
    GrantRequestCreateRequest,
    GrantRequestCreateResult,
    GrantRequestDecisionResult,
    SubjectToken,
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
    V1EnforceResponse,
    V1ObserveRequest,
    V1ObserveResponse,
    V1SimulateRequest,
    V1SimulateResponse,
)
from vinctor_service.observations import record_observation
from vinctor_service.service_config import DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS
from vinctor_service.simulations import simulate_v1_contract
from vinctor_service.sqlite_txn import (
    conn_txn_lock,
    require_serialized,
)
from vinctor_service.subject_tokens import mint_subject_token
from vinctor_service.v1_enforce import delegated_enforce_v1_contract, enforce_v1_contract


def init_sqlite_schema(conn: sqlite3.Connection) -> None:
    """Create/upgrade the schema, serialized on the connection lock.

    ``executescript`` (and the per-migration commits) implicitly commit any
    pending transaction on the connection, so this MUST hold ``conn_txn_lock``
    for the whole migration or it would commit a peer thread's open write on a
    shared connection. The lock is taken FIRST, so a concurrent write on another
    thread WAITS here instead of being mistaken for caller nesting; once held,
    ``in_transaction`` reflects only this thread — a True value means this
    thread's caller already owns a transaction, which schema init rejects (it
    must own its transaction, since its commits would otherwise seal the
    caller's partial write).
    """
    conn = require_serialized(conn)
    with conn_txn_lock(conn):
        if conn.in_transaction:
            raise RuntimeError(
                "schema initialization cannot run inside an open transaction; it "
                "must own its transaction so its commits do not seal a caller's "
                "partial write"
            )
        _apply_sqlite_schema(conn)


def _apply_sqlite_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            applied_at TEXT NOT NULL
        );

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

        CREATE TABLE IF NOT EXISTS local_keys (
            key_id TEXT PRIMARY KEY,
            key_type TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            agent_id TEXT,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT
        );

        CREATE TABLE IF NOT EXISTS agent_issuable_scope_bounds (
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            max_ttl_seconds INTEGER,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(workspace_id, agent_id)
        );

        CREATE TABLE IF NOT EXISTS grant_requests (
            request_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            requester_agent_id TEXT NOT NULL,
            target_agent_id TEXT NOT NULL,
            requested_scopes_json TEXT NOT NULL,
            requested_ttl_seconds INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            decided_at TEXT,
            decided_by TEXT,
            decision_reason TEXT,
            issued_grant_ref TEXT,
            task_id TEXT,
            session_id TEXT,
            boundary_id TEXT,
            requester_runtime TEXT,
            repo TEXT,
            worktree TEXT
        );

        CREATE TABLE IF NOT EXISTS auto_approval_rules (
            rule_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            name TEXT NOT NULL,
            target_agent_id TEXT NOT NULL,
            allowed_scopes_json TEXT NOT NULL,
            max_ttl_seconds INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_by TEXT,
            updated_at TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_local_keys_hash
        ON local_keys(key_hash);

        CREATE INDEX IF NOT EXISTS idx_local_keys_workspace
        ON local_keys(workspace_id);

        CREATE INDEX IF NOT EXISTS idx_grant_requests_workspace
        ON grant_requests(workspace_id);

        CREATE INDEX IF NOT EXISTS idx_auto_approval_rules_workspace
        ON auto_approval_rules(workspace_id);

        CREATE TABLE IF NOT EXISTS subject_tokens (
            token_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            grant_ref TEXT NOT NULL,
            audience TEXT NOT NULL,
            issued_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            revoked_at TEXT,
            bound_action TEXT,
            bound_resource TEXT,
            pop_secret TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_subject_tokens_hash
        ON subject_tokens(token_hash);

        CREATE TABLE IF NOT EXISTS agent_enforcement_settings (
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            require_boundary INTEGER NOT NULL DEFAULT 0,
            require_boundary_set INTEGER NOT NULL DEFAULT 0,
            require_subject_token INTEGER NOT NULL DEFAULT 0,
            require_subject_token_set INTEGER NOT NULL DEFAULT 0,
            require_pop INTEGER NOT NULL DEFAULT 0,
            require_pop_set INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (workspace_id, agent_id)
        );

        CREATE TABLE IF NOT EXISTS pop_replay_nonces (
            token_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ts INTEGER NOT NULL,
            PRIMARY KEY (token_id, nonce)
        );

        CREATE TABLE IF NOT EXISTS policy_versions (
            workspace_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            action TEXT NOT NULL,
            source_version INTEGER,
            snapshot_json TEXT NOT NULL,
            applied_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (workspace_id, version)
        );

        CREATE INDEX IF NOT EXISTS idx_pop_replay_nonces_ts
        ON pop_replay_nonces(ts);

        CREATE INDEX IF NOT EXISTS idx_audit_events_workspace
        ON audit_events(workspace_id);
        """
    )
    _ensure_grant_request_metadata_columns(conn)
    _ensure_scope_bounds_max_ttl_column(conn)
    _ensure_subject_tokens_revoked_at_column(conn)
    _ensure_subject_tokens_bound_columns(conn)
    _ensure_subject_tokens_pop_secret_column(conn)
    _ensure_agent_enforcement_require_subject_token_column(conn)
    _ensure_agent_enforcement_require_pop_column(conn)
    _ensure_agent_enforcement_require_boundary_set_column(conn)
    _ensure_agent_enforcement_require_subject_token_set_column(conn)
    _ensure_agent_enforcement_require_pop_set_column(conn)
    _ensure_audit_events_hashchain_columns(conn)
    _ensure_audit_events_event_class_column(conn)
    _ensure_audit_events_subject_token_verified_column(conn)
    _realign_agent_enforcement_require_boundary_set(conn)
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (1, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (2, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (3, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (4, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (5, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (6, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (7, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (8, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (9, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (10, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (11, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (12, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (13, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (_AUDIT_HASHCHAIN_BACKFILL_VERSION, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (15, datetime.now(UTC).isoformat()),
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO schema_migrations (version, applied_at)
        VALUES (?, ?)
        """,
        (16, datetime.now(UTC).isoformat()),
    )
    conn.commit()


def insert_grant(conn: sqlite3.Connection, grant: Grant) -> None:
    conn = require_serialized(conn)
    existing = conn.execute(
        "SELECT 1 FROM grants WHERE grant_ref = ?",
        (grant.grant_ref,),
    ).fetchone()
    if existing is not None:
        raise ValueError(f"duplicate grant_ref: {grant.grant_ref}")

    with _write_scope(conn):
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


def _ensure_grant_request_metadata_columns(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(grant_requests)").fetchall()
    }
    columns = {
        "task_id": "TEXT",
        "session_id": "TEXT",
        "boundary_id": "TEXT",
        "requester_runtime": "TEXT",
        "repo": "TEXT",
        "worktree": "TEXT",
    }
    for name, column_type in columns.items():
        if name not in existing_columns:
            conn.execute(f"ALTER TABLE grant_requests ADD COLUMN {name} {column_type}")


def _ensure_scope_bounds_max_ttl_column(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(agent_issuable_scope_bounds)").fetchall()
    }
    if "max_ttl_seconds" not in existing_columns:
        conn.execute(
            "ALTER TABLE agent_issuable_scope_bounds ADD COLUMN max_ttl_seconds INTEGER"
        )


def _ensure_subject_tokens_revoked_at_column(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(subject_tokens)").fetchall()
    }
    if "revoked_at" not in existing_columns:
        conn.execute("ALTER TABLE subject_tokens ADD COLUMN revoked_at TEXT")


def _ensure_subject_tokens_bound_columns(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(subject_tokens)").fetchall()
    }
    if "bound_action" not in existing_columns:
        conn.execute("ALTER TABLE subject_tokens ADD COLUMN bound_action TEXT")
    if "bound_resource" not in existing_columns:
        conn.execute("ALTER TABLE subject_tokens ADD COLUMN bound_resource TEXT")


def _ensure_subject_tokens_pop_secret_column(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(subject_tokens)").fetchall()
    }
    if "pop_secret" not in existing_columns:
        conn.execute("ALTER TABLE subject_tokens ADD COLUMN pop_secret TEXT")


def _ensure_agent_enforcement_require_subject_token_column(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(agent_enforcement_settings)").fetchall()
    }
    if "require_subject_token" not in existing_columns:
        conn.execute(
            "ALTER TABLE agent_enforcement_settings "
            "ADD COLUMN require_subject_token INTEGER NOT NULL DEFAULT 0"
        )


def _ensure_agent_enforcement_require_pop_column(conn: sqlite3.Connection) -> None:
    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(agent_enforcement_settings)").fetchall()
    }
    if "require_pop" not in existing_columns:
        conn.execute(
            "ALTER TABLE agent_enforcement_settings "
            "ADD COLUMN require_pop INTEGER NOT NULL DEFAULT 0"
        )


def _ensure_agent_enforcement_require_boundary_set_column(
    conn: sqlite3.Connection,
) -> None:
    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(agent_enforcement_settings)").fetchall()
    }
    if "require_boundary_set" not in existing_columns:
        # Existing rows previously always acted as explicit boundary overrides.
        # Defaulting migrated rows to 1 preserves that behavior; freshly created
        # schemas default to 0 so unrelated settings do not create an override.
        # _realign_agent_enforcement_require_boundary_set then corrects the
        # preserve-all default to the fail-closed value-derived presence.
        conn.execute(
            "ALTER TABLE agent_enforcement_settings "
            "ADD COLUMN require_boundary_set INTEGER NOT NULL DEFAULT 1"
        )


def _ensure_agent_enforcement_require_subject_token_set_column(
    conn: sqlite3.Connection,
) -> None:
    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(agent_enforcement_settings)").fetchall()
    }
    if "require_subject_token_set" not in existing_columns:
        # Fail closed: a migrated row counts as an explicit setting only where
        # its value is already TRUE. A FALSE value becomes "unset" and falls
        # through to the workspace mandate instead of silently exempting the
        # agent. Runs once, when the column is first added.
        conn.execute(
            "ALTER TABLE agent_enforcement_settings "
            "ADD COLUMN require_subject_token_set INTEGER NOT NULL DEFAULT 0"
        )
        conn.execute(
            "UPDATE agent_enforcement_settings "
            "SET require_subject_token_set = require_subject_token"
        )


def _ensure_agent_enforcement_require_pop_set_column(
    conn: sqlite3.Connection,
) -> None:
    existing_columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(agent_enforcement_settings)").fetchall()
    }
    if "require_pop_set" not in existing_columns:
        # Fail closed, mirroring require_subject_token_set above.
        conn.execute(
            "ALTER TABLE agent_enforcement_settings "
            "ADD COLUMN require_pop_set INTEGER NOT NULL DEFAULT 0"
        )
        conn.execute(
            "UPDATE agent_enforcement_settings SET require_pop_set = require_pop"
        )


def _realign_agent_enforcement_require_boundary_set(conn: sqlite3.Connection) -> None:
    # One-time, version-gated realignment (schema version 13). The original
    # require_boundary_set migration defaulted migrated rows to 1, so a row
    # that only ever carried require_subject_token / require_pop read as an
    # explicit require_boundary=false override, silently exempting the agent
    # from a workspace-wide boundary mandate. Fail closed: mark boundary "set"
    # only where require_boundary is already TRUE. Gated on the version record
    # (this UPDATE is not idempotent by itself) so an explicit exemption
    # written after the upgrade is never clobbered by a later init.
    already_applied = conn.execute(
        "SELECT 1 FROM schema_migrations WHERE version = ?",
        (13,),
    ).fetchone()
    if already_applied is None:
        conn.execute(
            "UPDATE agent_enforcement_settings SET require_boundary_set = require_boundary"
        )


# schema_migrations sentinel marking the audit hash-chain backfill complete.
# While absent, the one-time backfill of pre-hash-chain rows may run; once
# recorded, the backfill never runs again (a later NULL row_hash is treated as
# tampering and left for verify_chain to fail closed on).
_AUDIT_HASHCHAIN_BACKFILL_VERSION = 14


def _ensure_audit_events_hashchain_columns(conn: sqlite3.Connection) -> None:
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
    }
    if "seq" not in cols:
        conn.execute("ALTER TABLE audit_events ADD COLUMN seq INTEGER")
    if "prev_hash" not in cols:
        conn.execute("ALTER TABLE audit_events ADD COLUMN prev_hash TEXT")
    if "row_hash" not in cols:
        conn.execute("ALTER TABLE audit_events ADD COLUMN row_hash TEXT")

    # The backfill is a ONE-TIME migration of pre-hash-chain rows, gated on the
    # sentinel below. Once it is recorded, a NULL row_hash is no longer
    # un-migrated data — it is tampering or corruption — so we must NOT silently
    # re-chain it into a valid-looking entry (that would mask the tamper).
    # verify_chain fails closed on the NULL instead.
    backfill_done = conn.execute(
        "SELECT 1 FROM schema_migrations WHERE version = ?",
        (_AUDIT_HASHCHAIN_BACKFILL_VERSION,),
    ).fetchone()
    unchained: tuple = ()
    if backfill_done is None:
        # Resumable: always continues from the current chained head, so an
        # interrupted run completes on a later startup (until the sentinel is
        # recorded alongside the other versions in init_sqlite_schema).
        unchained = conn.execute(
            "SELECT rowid, event_json FROM audit_events "
            "WHERE row_hash IS NULL ORDER BY rowid"
        ).fetchall()
        if unchained:
            start_seq_row = conn.execute(
                "SELECT COALESCE(MAX(seq), 0), "
                "(SELECT row_hash FROM audit_events WHERE seq = (SELECT MAX(seq) "
                "FROM audit_events WHERE row_hash IS NOT NULL)) "
                "FROM audit_events WHERE row_hash IS NOT NULL"
            ).fetchone()
            seq = start_seq_row[0] or 0
            prev = start_seq_row[1] or GENESIS_PREV_HASH
            for rowid, event_json in unchained:
                seq += 1
                rh = row_hash(seq, event_json, prev)
                conn.execute(
                    "UPDATE audit_events SET seq = ?, prev_hash = ?, row_hash = ? "
                    "WHERE rowid = ?",
                    (seq, prev, rh, rowid),
                )
                prev = rh

    # Defense-in-depth against a forked chain: seq is the tamper-evident, hashed
    # ordering key, so forbid duplicate seq values. SQLite unique indexes permit
    # multiple NULLs, so this is safe before the backfill populates seq.
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_events_seq ON audit_events(seq)"
    )
    conn.commit()


def _ensure_audit_events_event_class_column(conn: sqlite3.Connection) -> None:
    # Schema version 15 (ADR 0019): audit events carry an event category on the
    # SAME chain — "decision" (what an agent did) or "control" (an operator
    # changed the rules). The non-NULL default backfills every pre-existing row
    # as "decision", matching its canonical event_json, which omits the key for
    # that class — so the migration touches no hashed bytes and verify_chain is
    # unaffected.
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
    }
    if "event_class" not in cols:
        conn.execute(
            "ALTER TABLE audit_events "
            "ADD COLUMN event_class TEXT NOT NULL DEFAULT 'decision'"
        )


def _ensure_audit_events_subject_token_verified_column(
    conn: sqlite3.Connection,
) -> None:
    """Schema v16: materialize the renamed audit field without rehashing JSON."""
    cols = {
        row[1] for row in conn.execute("PRAGMA table_info(audit_events)").fetchall()
    }
    if "identity_proven" in cols and "subject_token_verified" not in cols:
        conn.execute(
            "ALTER TABLE audit_events RENAME COLUMN identity_proven "
            "TO subject_token_verified"
        )
    elif "subject_token_verified" not in cols:
        conn.execute(
            "ALTER TABLE audit_events ADD COLUMN "
            "subject_token_verified INTEGER NOT NULL DEFAULT 0"
        )
        # SQLite historically kept this field JSON-only. Backfill the new
        # crosscheck column from either JSON spelling while leaving event_json
        # and its row_hash bytes untouched.
        conn.execute(
            """
            UPDATE audit_events
            SET subject_token_verified = COALESCE(
                json_extract(event_json, '$.subject_token_verified'),
                json_extract(event_json, '$.identity_proven'),
                0
            )
            """
        )


def get_sqlite_schema_versions(conn: sqlite3.Connection) -> tuple[int, ...]:
    rows = conn.execute(
        """
        SELECT version
        FROM schema_migrations
        ORDER BY version
        """
    ).fetchall()
    return tuple(row[0] for row in rows)


class SQLiteGrantRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = require_serialized(conn)

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

        return _grant_from_row(row)

    def list_grants_for_workspace(
        self,
        workspace_id: str,
        *,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]:
        clauses = ["workspace_id = ?"]
        params: list[str] = [workspace_id]
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
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
        return tuple(_grant_from_row(row) for row in rows)

    def insert(self, grant: Grant) -> None:
        insert_grant(self._conn, grant)

    def revoke(self, *, grant_ref: str, workspace_id: str) -> Grant | None:
        grant = self.get_by_ref(grant_ref)
        if grant is None or grant.workspace_id != workspace_id:
            return None
        if grant.status == "revoked":
            return grant

        with _write_scope(self._conn):
            self._conn.execute(
                """
                UPDATE grants
                SET status = 'revoked'
                WHERE grant_ref = ? AND workspace_id = ?
                """,
                (grant_ref, workspace_id),
            )
        revoked = self.get_by_ref(grant_ref)
        if revoked is None:
            raise RuntimeError(f"grant disappeared during revocation: {grant_ref}")
        return revoked


@contextmanager
def _write_scope(conn: sqlite3.Connection) -> Iterator[None]:
    """Commit scope for a single repository write.

    Standalone calls take SQLite's write-reservation lock up front with ``BEGIN
    IMMEDIATE`` and commit (or roll back) on exit. When the caller already holds an
    explicit transaction (an all-or-nothing BEGIN IMMEDIATE unit of work),
    sqlite3's connection context manager must NOT be entered — its exit would
    commit the caller's WHOLE transaction mid-way — so the write joins the open
    transaction instead and the outer owner commits or rolls back everything.

    The whole scope runs under the shared per-connection re-entrant lock so two
    threads sharing one connection cannot interleave (or one commit/join the
    other's transaction through the connection-global ``in_transaction`` flag);
    same-thread nesting re-enters the lock freely. EVERY write path on the
    connection must use this (or _atomic_write) for the serialization to hold.
    """
    with conn_txn_lock(conn):
        if conn.in_transaction:
            yield
            return
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield
            conn.commit()
        except BaseException:
            conn.rollback()
            raise


@contextmanager
def _atomic_write(conn: sqlite3.Connection) -> Iterator[None]:
    """One BEGIN IMMEDIATE transaction wrapping a whole state-plus-audit change.

    Every state write and its audit row commit together or not at all — an
    audit-writer failure OR a failing commit rolls the state change back rather
    than leaving it unrecorded. The shared per-connection re-entrant lock
    serializes the whole scope so two threads sharing one connection cannot be
    folded into one transaction; BEGIN IMMEDIATE additionally serializes writers
    across connections/processes. Same-thread service nesting re-enters the lock
    and joins the open transaction. Deferred audit anchor/export emissions are
    bracketed by atomic_write_deferral: they flush only after this commit and are
    dropped on rollback or a failing commit.
    """
    with conn_txn_lock(conn):
        if conn.in_transaction:
            yield
            return
        with conn.atomic_write_deferral():
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield
                conn.commit()
            except BaseException:
                conn.rollback()
                raise


class SQLiteAgentIssuableScopeBoundsRepository:
    # ADR 0019: issuable scope bounds are control-plane state, so the repository
    # cannot exist without an audit path — the auditor is a required argument
    # and must write through THIS connection (one transaction, one commit).
    def __init__(
        self, conn: sqlite3.Connection, control_auditor: ControlPlaneAuditor
    ) -> None:
        self._conn = require_serialized(conn)
        control_auditor.require_bound_to(self._conn)
        self._control_auditor = control_auditor

    def get_bounds(self, *, workspace_id: str, agent_id: str) -> tuple[str, ...] | None:
        row = self._conn.execute(
            """
            SELECT scopes_json
            FROM agent_issuable_scope_bounds
            WHERE workspace_id = ? AND agent_id = ?
            """,
            (workspace_id, agent_id),
        ).fetchone()
        if row is None:
            return None
        return tuple(json.loads(row[0]))

    def get_max_ttl_seconds(self, *, workspace_id: str, agent_id: str) -> int | None:
        row = self._conn.execute(
            """
            SELECT max_ttl_seconds
            FROM agent_issuable_scope_bounds
            WHERE workspace_id = ? AND agent_id = ?
            """,
            (workspace_id, agent_id),
        ).fetchone()
        if row is None:
            return None
        return row[0]

    def get_bounds_with_max_ttl(
        self, *, workspace_id: str, agent_id: str
    ) -> AgentIssuableBounds | None:
        # Single-row read: scopes and max TTL come from one consistent snapshot
        # of the bounds row (no torn read across a concurrent set_bounds).
        row = self._conn.execute(
            """
            SELECT scopes_json, max_ttl_seconds
            FROM agent_issuable_scope_bounds
            WHERE workspace_id = ? AND agent_id = ?
            """,
            (workspace_id, agent_id),
        ).fetchone()
        if row is None:
            return None
        return AgentIssuableBounds(
            scopes=tuple(json.loads(row[0])),
            max_ttl_seconds=row[1],
        )

    def list_bounds_for_workspace(self, workspace_id: str) -> ScopeBoundsListing:
        rows = self._conn.execute(
            """
            SELECT agent_id, scopes_json
            FROM agent_issuable_scope_bounds
            WHERE workspace_id = ?
            ORDER BY agent_id
            """,
            (workspace_id,),
        ).fetchall()
        return tuple((row[0], tuple(json.loads(row[1]))) for row in rows)

    def set_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        now: datetime,
    ) -> None:
        validate_issuable_scope_bounds(scopes, max_ttl_seconds=max_ttl_seconds)
        # The bounds change and its control audit event commit as ONE unit.
        with _atomic_write(self._conn):
            self._conn.execute(
                """
                INSERT INTO agent_issuable_scope_bounds (
                    workspace_id, agent_id, scopes_json, max_ttl_seconds, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    scopes_json = excluded.scopes_json,
                    max_ttl_seconds = excluded.max_ttl_seconds,
                    updated_at = excluded.updated_at
                """,
                (
                    workspace_id,
                    agent_id,
                    json.dumps(list(scopes)),
                    max_ttl_seconds,
                    now.isoformat(),
                ),
            )
            self._control_auditor.record(
                event_type=EVENT_SCOPE_BOUNDS_SET,
                workspace_id=workspace_id,
                agent_id=agent_id,
                action="set_issuable_scope_bounds",
                resource=f"issuable_scope_bounds/{agent_id}",
                reason="max_ttl_seconds="
                + (str(max_ttl_seconds) if max_ttl_seconds is not None else "none"),
                scope_attempted=" ".join(scopes),
                now=now,
            )


class SQLiteAgentEnforcementSettingsRepository:
    # ADR 0019: the enforcement mandates are control-plane state, so the
    # repository cannot exist without an audit path — the auditor is required
    # and must write through THIS connection (one transaction, one commit).
    def __init__(
        self, conn: sqlite3.Connection, control_auditor: ControlPlaneAuditor
    ) -> None:
        self._conn = require_serialized(conn)
        control_auditor.require_bound_to(self._conn)
        self._control_auditor = control_auditor

    def _record_setting_change(
        self, *, setting: str, value: bool, workspace_id: str, agent_id: str,
        now: datetime,
    ) -> None:
        self._control_auditor.record(
            event_type=EVENT_ENFORCEMENT_SETTING_CHANGED,
            workspace_id=workspace_id,
            agent_id=agent_id,
            action=f"set_{setting}",
            resource=f"enforcement_setting/{setting}",
            reason=f"{setting}={'true' if value else 'false'}",
            now=now,
        )

    def get_require_boundary(self, *, workspace_id: str, agent_id: str) -> bool:
        row = self._conn.execute(
            """
            SELECT require_boundary FROM agent_enforcement_settings
            WHERE workspace_id = ? AND agent_id = ?
            """,
            (workspace_id, agent_id),
        ).fetchone()
        return bool(row[0]) if row is not None else False

    def get_require_boundary_setting(self, *, workspace_id: str, agent_id: str) -> bool | None:
        row = self._conn.execute(
            """
            SELECT require_boundary FROM agent_enforcement_settings
            WHERE workspace_id = ? AND agent_id = ? AND require_boundary_set = 1
            """,
            (workspace_id, agent_id),
        ).fetchone()
        return bool(row[0]) if row is not None else None

    def is_boundary_required(self, *, workspace_id: str, agent_id: str) -> bool:
        agent = self.get_require_boundary_setting(workspace_id=workspace_id, agent_id=agent_id)
        if agent is not None:
            return agent
        ws = self.get_require_boundary_setting(workspace_id=workspace_id, agent_id="")
        return ws if ws is not None else False

    def list_require_boundary(self, workspace_id: str) -> tuple[tuple[str, bool], ...]:
        rows = self._conn.execute(
            """
            SELECT agent_id, require_boundary FROM agent_enforcement_settings
            WHERE workspace_id = ? AND require_boundary_set = 1
            ORDER BY agent_id
            """,
            (workspace_id,),
        ).fetchall()
        return tuple((row[0], bool(row[1])) for row in rows)

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime
    ) -> None:
        # The mandate change and its control audit event commit as ONE unit.
        with _atomic_write(self._conn):
            self._conn.execute(
                """
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, require_boundary, require_boundary_set,
                    require_subject_token_set, require_pop_set, updated_at
                ) VALUES (?, ?, ?, 1, 0, 0, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    require_boundary = excluded.require_boundary,
                    require_boundary_set = 1,
                    updated_at = excluded.updated_at
                """,
                (workspace_id, agent_id, 1 if require_boundary else 0, now.isoformat()),
            )
            self._record_setting_change(
                setting="require_boundary", value=require_boundary,
                workspace_id=workspace_id, agent_id=agent_id, now=now,
            )

    def get_require_subject_token_setting(
        self, *, workspace_id: str, agent_id: str
    ) -> bool | None:
        row = self._conn.execute(
            """
            SELECT require_subject_token FROM agent_enforcement_settings
            WHERE workspace_id = ? AND agent_id = ? AND require_subject_token_set = 1
            """,
            (workspace_id, agent_id),
        ).fetchone()
        return bool(row[0]) if row is not None else None

    def is_subject_token_required(self, *, workspace_id: str, agent_id: str) -> bool:
        agent = self.get_require_subject_token_setting(
            workspace_id=workspace_id, agent_id=agent_id
        )
        if agent is not None:
            return agent
        ws = self.get_require_subject_token_setting(workspace_id=workspace_id, agent_id="")
        return ws if ws is not None else False

    def set_require_subject_token(
        self, *, workspace_id: str, agent_id: str, require_subject_token: bool, now: datetime
    ) -> None:
        with _atomic_write(self._conn):
            self._conn.execute(
                """
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, require_subject_token, require_subject_token_set,
                    require_boundary_set, require_pop_set, updated_at
                ) VALUES (?, ?, ?, 1, 0, 0, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    require_subject_token = excluded.require_subject_token,
                    require_subject_token_set = 1,
                    updated_at = excluded.updated_at
                """,
                (workspace_id, agent_id, 1 if require_subject_token else 0, now.isoformat()),
            )
            self._record_setting_change(
                setting="require_subject_token", value=require_subject_token,
                workspace_id=workspace_id, agent_id=agent_id, now=now,
            )

    def get_require_pop_setting(self, *, workspace_id: str, agent_id: str) -> bool | None:
        row = self._conn.execute(
            """
            SELECT require_pop FROM agent_enforcement_settings
            WHERE workspace_id = ? AND agent_id = ? AND require_pop_set = 1
            """,
            (workspace_id, agent_id),
        ).fetchone()
        return bool(row[0]) if row is not None else None

    def is_pop_required(self, *, workspace_id: str, agent_id: str) -> bool:
        agent = self.get_require_pop_setting(workspace_id=workspace_id, agent_id=agent_id)
        if agent is not None:
            return agent
        ws = self.get_require_pop_setting(workspace_id=workspace_id, agent_id="")
        return ws if ws is not None else False

    def set_require_pop(
        self, *, workspace_id: str, agent_id: str, require_pop: bool, now: datetime
    ) -> None:
        with _atomic_write(self._conn):
            self._conn.execute(
                """
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, require_pop, require_pop_set,
                    require_boundary_set, require_subject_token_set, updated_at
                ) VALUES (?, ?, ?, 1, 0, 0, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    require_pop = excluded.require_pop,
                    require_pop_set = 1,
                    updated_at = excluded.updated_at
                """,
                (workspace_id, agent_id, 1 if require_pop else 0, now.isoformat()),
            )
            self._record_setting_change(
                setting="require_pop", value=require_pop,
                workspace_id=workspace_id, agent_id=agent_id, now=now,
            )


class SQLiteGrantRequestRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = require_serialized(conn)

    def insert_request(self, request: GrantRequest) -> None:
        if self.get_request(request.request_id) is not None:
            raise ValueError(f"duplicate grant request_id: {request.request_id}")
        with _write_scope(self._conn):
            self._conn.execute(
                """
                INSERT INTO grant_requests (
                    request_id, workspace_id, requester_agent_id, target_agent_id,
                    requested_scopes_json, requested_ttl_seconds, reason, status,
                    created_at, decided_at, decided_by, decision_reason,
                    issued_grant_ref, task_id, session_id, boundary_id,
                    requester_runtime, repo, worktree
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _grant_request_values(request),
            )

    def get_request(self, request_id: str) -> GrantRequest | None:
        row = self._conn.execute(
            """
            SELECT request_id, workspace_id, requester_agent_id, target_agent_id,
                   requested_scopes_json, requested_ttl_seconds, reason, status,
                   created_at, decided_at, decided_by, decision_reason,
                   issued_grant_ref, task_id, session_id, boundary_id,
                   requester_runtime, repo, worktree
            FROM grant_requests
            WHERE request_id = ?
            """,
            (request_id,),
        ).fetchone()
        return _grant_request_from_row(row)

    def list_requests_for_workspace(self, workspace_id: str) -> tuple[GrantRequest, ...]:
        rows = self._conn.execute(
            """
            SELECT request_id, workspace_id, requester_agent_id, target_agent_id,
                   requested_scopes_json, requested_ttl_seconds, reason, status,
                   created_at, decided_at, decided_by, decision_reason,
                   issued_grant_ref, task_id, session_id, boundary_id,
                   requester_runtime, repo, worktree
            FROM grant_requests
            WHERE workspace_id = ?
            ORDER BY created_at, request_id
            """,
            (workspace_id,),
        ).fetchall()
        return tuple(
            request
            for row in rows
            if (request := _grant_request_from_row(row)) is not None
        )

    def update_request(self, request: GrantRequest) -> None:
        if self.get_request(request.request_id) is None:
            raise ValueError(f"unknown grant request_id: {request.request_id}")
        with _write_scope(self._conn):
            self._conn.execute(
                """
                UPDATE grant_requests
                SET workspace_id = ?,
                    requester_agent_id = ?,
                    target_agent_id = ?,
                    requested_scopes_json = ?,
                    requested_ttl_seconds = ?,
                    reason = ?,
                    status = ?,
                    created_at = ?,
                    decided_at = ?,
                    decided_by = ?,
                    decision_reason = ?,
                    issued_grant_ref = ?,
                    task_id = ?,
                    session_id = ?,
                    boundary_id = ?,
                    requester_runtime = ?,
                    repo = ?,
                    worktree = ?
                WHERE request_id = ?
                """,
                (
                    request.workspace_id,
                    request.requester_agent_id,
                    request.target_agent_id,
                    json.dumps(list(request.requested_scopes)),
                    request.requested_ttl_seconds,
                    request.reason,
                    request.status,
                    request.created_at.isoformat(),
                    _datetime_to_storage(request.decided_at),
                    request.decided_by,
                    request.decision_reason,
                    request.issued_grant_ref,
                    request.task_id,
                    request.session_id,
                    request.boundary_id,
                    request.requester_runtime,
                    request.repo,
                    request.worktree,
                    request.request_id,
                ),
            )

    def decide_request(self, request: GrantRequest) -> bool:
        with _write_scope(self._conn):
            cursor = self._conn.execute(
                """
                UPDATE grant_requests
                SET status = ?,
                    decided_at = ?,
                    decided_by = ?,
                    decision_reason = ?,
                    issued_grant_ref = ?
                WHERE request_id = ? AND status = 'pending'
                """,
                (
                    request.status,
                    _datetime_to_storage(request.decided_at),
                    request.decided_by,
                    request.decision_reason,
                    request.issued_grant_ref,
                    request.request_id,
                ),
            )
            return cursor.rowcount == 1


class SQLiteReplayStore:
    """Durable, cross-process anti-replay for PoP nonces (ADR 0007 arc J).

    Drop-in for :class:`vinctor_service.pop.PopReplayCache`: duck-typed on the
    exact ``check_and_record`` signature, so ``verify_pop`` is unchanged. Unlike
    the in-memory cache, state survives a restart and is correct across processes
    because the ``(token_id, nonce)`` PRIMARY KEY enforces dedup at the db file.

    A bad or stale proof never reaches this store: ``verify_pop`` calls
    ``check_and_record`` only AFTER the mac compare + freshness window pass, so no
    durable row is ever written for a forged or expired proof.
    """

    def __init__(
        self,
        conn: sqlite3.Connection,
        max_entries: int = 10000,
        max_per_token: int = 256,
    ) -> None:
        self._conn = require_serialized(conn)
        self._max = max_entries
        # Per-token-id row cap. The global cap alone couples tenants: one token
        # could mint distinct fresh nonces up to ``max_entries`` and lock out
        # every OTHER token's fresh proof. Bounding each token_id's live footprint
        # to ``max_per_token`` keeps that flood self-contained — a token at its own
        # cap has its NEW proofs rejected (fail closed), never evicting any row —
        # so the global cap stays a generous backstop, not a cross-tenant lever.
        self._max_per_token = max_per_token

    def check_and_record(
        self, *, token_id: str, nonce: str, ts: int, now_unix: int, skew: int
    ) -> bool:
        cutoff = now_unix - skew
        # _write_scope holds the connection's re-entrant lock across the whole
        # check-then-insert, serializing it within-process; the PK +
        # IntegrityError below still covers cross-process/thread races.
        with _write_scope(self._conn):
            self._conn.execute(
                "DELETE FROM pop_replay_nonces WHERE ts < ?", (cutoff,)
            )
            row = self._conn.execute(
                "SELECT 1 FROM pop_replay_nonces WHERE token_id = ? AND nonce = ?",
                (token_id, nonce),
            ).fetchone()
            if row is not None:
                return False  # replay
            per_token = self._conn.execute(
                "SELECT COUNT(*) FROM pop_replay_nonces WHERE token_id = ?",
                (token_id,),
            ).fetchone()[0]
            if per_token >= self._max_per_token:
                # Expired rows were purged above, so this token's cap is full of
                # still-fresh nonces. NEVER evict a live nonce to make room
                # (ADR 0007): a dropped fresh nonce would let its captured proof
                # replay within the window. Fail closed (reject the new proof);
                # operators can raise the cap. The flood stays self-contained, so
                # it still cannot lock out other tenants.
                return False
            count = self._conn.execute(
                "SELECT COUNT(*) FROM pop_replay_nonces"
            ).fetchone()[0]
            if count >= self._max:
                return False  # full of fresh entries -> fail closed
            try:
                self._conn.execute(
                    "INSERT INTO pop_replay_nonces (token_id, nonce, ts) "
                    "VALUES (?, ?, ?)",
                    (token_id, nonce, ts),
                )
            except sqlite3.IntegrityError:
                # concurrent insert (cross-process/thread) of the same key
                return False  # replay
        return True


class SQLiteSubjectTokenRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = require_serialized(conn)

    def insert(self, token: SubjectToken) -> None:
        if self.get_by_hash(token.token_hash) is not None:
            raise ValueError(f"duplicate subject token_hash: {token.token_hash}")
        with _write_scope(self._conn):
            self._conn.execute(
                """
                INSERT INTO subject_tokens (
                    token_id, token_hash, workspace_id, agent_id, grant_ref,
                    audience, issued_at, expires_at, created_by, revoked_at,
                    bound_action, bound_resource, pop_secret
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token.token_id,
                    token.token_hash,
                    token.workspace_id,
                    token.agent_id,
                    token.grant_ref,
                    token.audience,
                    token.issued_at.isoformat(),
                    token.expires_at.isoformat(),
                    token.created_by,
                    _datetime_to_storage(token.revoked_at),
                    token.bound_action,
                    token.bound_resource,
                    token.pop_secret,
                ),
            )

    def get_by_hash(self, token_hash: str) -> SubjectToken | None:
        row = self._conn.execute(
            """
            SELECT token_id, token_hash, workspace_id, agent_id, grant_ref,
                   audience, issued_at, expires_at, created_by, revoked_at,
                   bound_action, bound_resource, pop_secret
            FROM subject_tokens
            WHERE token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        return _subject_token_from_row(row)

    def get_by_id(self, token_id: str) -> SubjectToken | None:
        row = self._conn.execute(
            """
            SELECT token_id, token_hash, workspace_id, agent_id, grant_ref,
                   audience, issued_at, expires_at, created_by, revoked_at,
                   bound_action, bound_resource
            FROM subject_tokens
            WHERE token_id = ?
            """,
            (token_id,),
        ).fetchone()
        return _subject_token_from_row(row)

    def revoke(self, token_id: str, *, now: datetime) -> bool:
        with _write_scope(self._conn):
            cursor = self._conn.execute(
                "UPDATE subject_tokens SET revoked_at = ? WHERE token_id = ?",
                (_datetime_to_storage(now), token_id),
            )
        return cursor.rowcount > 0

    def list_subject_tokens(self, workspace_id: str) -> tuple[SubjectToken, ...]:
        rows = self._conn.execute(
            """
            SELECT token_id, token_hash, workspace_id, agent_id, grant_ref,
                   audience, issued_at, expires_at, created_by, revoked_at,
                   bound_action, bound_resource
            FROM subject_tokens
            WHERE workspace_id = ?
            ORDER BY issued_at
            """,
            (workspace_id,),
        ).fetchall()
        return tuple(token for row in rows if (token := _subject_token_from_row(row)) is not None)


class SQLiteAutoApprovalRuleRepository:
    def __init__(
        self, conn: sqlite3.Connection, control_auditor: ControlPlaneAuditor
    ) -> None:
        self._conn = require_serialized(conn)
        control_auditor.require_bound_to(self._conn)
        self._control_auditor = control_auditor

    def add_rule(self, rule: AutoApprovalRule) -> None:
        if self.get_rule(rule.rule_id) is not None:
            raise ValueError(f"duplicate auto-approval rule_id: {rule.rule_id}")
        with _atomic_write(self._conn):
            self._conn.execute(
                """
                INSERT INTO auto_approval_rules (
                    rule_id, workspace_id, name, target_agent_id,
                    allowed_scopes_json, max_ttl_seconds, status,
                    created_by, created_at, updated_by, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                _auto_approval_rule_values(rule),
            )
            self._control_auditor.record(
                event_type=EVENT_AUTO_APPROVAL_RULE_CREATED,
                workspace_id=rule.workspace_id,
                action="create_auto_approval_rule",
                resource=f"auto_approval_rule/{rule.rule_id}",
                reason=f"status={rule.status}",
                now=rule.created_at,
            )

    def get_rule(self, rule_id: str) -> AutoApprovalRule | None:
        row = self._conn.execute(
            """
            SELECT rule_id, workspace_id, name, target_agent_id,
                   allowed_scopes_json, max_ttl_seconds, status,
                   created_by, created_at, updated_by, updated_at
            FROM auto_approval_rules
            WHERE rule_id = ?
            """,
            (rule_id,),
        ).fetchone()
        return _auto_approval_rule_from_row(row)

    def list_rules_for_workspace(self, workspace_id: str) -> tuple[AutoApprovalRule, ...]:
        rows = self._conn.execute(
            """
            SELECT rule_id, workspace_id, name, target_agent_id,
                   allowed_scopes_json, max_ttl_seconds, status,
                   created_by, created_at, updated_by, updated_at
            FROM auto_approval_rules
            WHERE workspace_id = ?
            ORDER BY created_at, rule_id
            """,
            (workspace_id,),
        ).fetchall()
        return tuple(
            rule
            for row in rows
            if (rule := _auto_approval_rule_from_row(row)) is not None
        )

    def update_rule(self, rule: AutoApprovalRule) -> None:
        if self.get_rule(rule.rule_id) is None:
            raise ValueError(f"unknown auto-approval rule_id: {rule.rule_id}")
        with _atomic_write(self._conn):
            self._conn.execute(
                """
                UPDATE auto_approval_rules
                SET workspace_id = ?,
                    name = ?,
                    target_agent_id = ?,
                    allowed_scopes_json = ?,
                    max_ttl_seconds = ?,
                    status = ?,
                    created_by = ?,
                    created_at = ?,
                    updated_by = ?,
                    updated_at = ?
                WHERE rule_id = ?
                """,
                (
                    rule.workspace_id,
                    rule.name,
                    rule.target_agent_id,
                    json.dumps(list(rule.allowed_scopes)),
                    rule.max_ttl_seconds,
                    rule.status,
                    rule.created_by,
                    rule.created_at.isoformat(),
                    rule.updated_by,
                    _datetime_to_storage(rule.updated_at),
                    rule.rule_id,
                ),
            )
            if rule.status == "disabled":
                self._control_auditor.record(
                    event_type=EVENT_AUTO_APPROVAL_RULE_DISABLED,
                    workspace_id=rule.workspace_id,
                    action="disable_auto_approval_rule",
                    resource=f"auto_approval_rule/{rule.rule_id}",
                    reason="status=disabled",
                    now=rule.updated_at or rule.created_at,
                )


class SQLiteAuditWriter:
    def __init__(self, conn: sqlite3.Connection, anchor: AuditAnchor | None = None) -> None:
        self._conn = require_serialized(conn)
        self._anchor = anchor if anchor is not None else NullAnchor()

    def write(self, event: AuditEvent) -> None:
        event_data = event.to_dict()
        event_json = json.dumps(event_data, sort_keys=True)
        with _write_scope(self._conn):
            head = self._conn.execute(
                "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            prev_seq = head[0] if head else 0
            prev_hash = head[1] if head else GENESIS_PREV_HASH
            seq = prev_seq + 1
            rh = row_hash(seq, event_json, prev_hash)
            self._conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, event_type, decision, reason,
                    workspace_id, agent_id, grant_id, grant_ref,
                    action, resource, scope_attempted, scope_matched,
                    boundary_id, runtime, boundary_type, created_at,
                    subject_token_verified, event_class, event_json,
                    seq, prev_hash, row_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event.subject_token_verified,
                    event.event_class,
                    event_json,
                    seq,
                    prev_hash,
                    rh,
                ),
            )
        # Emit the external anchor only after the row is DURABLY committed:
        # inline for a standalone write, deferred to the outermost commit when
        # this write joined an open transaction — so the anchor never records a
        # chain head a later rollback removes. Fail-open either way.
        created = event.created_at.isoformat()
        self.emit_or_defer(lambda: self._anchor.emit(seq, rh, created))

    def emit_or_defer(self, emission: Callable[[], None]) -> None:
        """Run a post-commit audit side effect (anchor/export) now, or defer it
        to this connection's active _atomic_write commit if one is active on this
        thread (dropped on rollback/commit-failure). Fail-open."""
        self._conn.emit_or_defer(emission)

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
        # Order by the tamper-evident chain sequence (baked into row_hash), not
        # the unprotected SQLite rowid.
        rows = self._conn.execute(
            """
            SELECT event_json
            FROM audit_events
            ORDER BY seq
            """
        ).fetchall()
        return [_audit_event_from_json(row[0]) for row in rows]

    def list_auth_failures(self, *, limit: int) -> tuple[AuditEvent, ...]:
        rows = self._conn.execute(
            """
            SELECT event_json FROM audit_events
            WHERE workspace_id = '' AND event_type = 'auth_failed'
            ORDER BY seq DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return tuple(_audit_event_from_json(row[0]) for row in reversed(rows))

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
        subject_token_verified: bool | None = None,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        """Workspace-scoped, SQL-pushed audit filter.

        Mirrors the HTTP/operator Python-side filter EXACTLY (same WHERE
        semantics, same ordering) but lets SQLite do the work: a parameterized
        ``WHERE workspace_id = ? [AND ...] ORDER BY seq DESC [LIMIT ?]`` so the
        whole table is never materialized into Python. The most-recent ``limit``
        rows are selected via ``seq DESC LIMIT`` and then returned oldest-first
        within that window, matching the legacy ``[-limit:]`` slice of
        insertion-ordered events. Ordering is by the tamper-evident chain
        ``seq`` (hashed into row_hash), not the unprotected rowid.
        ``limit=None`` returns every matching row.

        ``reason_code``/``enforcing_principal`` have no dedicated columns; they
        are filtered via ``json_extract`` over the
        canonical ``event_json`` (JSON paths are literals, values are bound
        parameters). ``AuditEvent.to_dict`` omits these keys when unset, so an
        absent key reads as SQL NULL and never matches a string filter.
        ``subject_token_verified`` uses its v16 materialized column.

        Workspace scoping is mandatory: results never cross tenants. Every value
        travels as a bound parameter (no string interpolation into SQL).
        """
        clauses = ["workspace_id = ?"]
        params: list[object] = [workspace_id]
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if grant_ref is not None:
            clauses.append("grant_ref = ?")
            params.append(grant_ref)
        if boundary_id is not None:
            clauses.append("boundary_id = ?")
            params.append(boundary_id)
        if agent_id is not None:
            clauses.append("agent_id = ?")
            params.append(agent_id)
        if request_id is not None:
            clauses.append("(resource = ? OR grant_ref = ?)")
            params.append(f"grant_request/{request_id}")
            params.append(request_id)
        if reason_code is not None:
            clauses.append("json_extract(event_json, '$.reason_code') = ?")
            params.append(reason_code)
        if enforcing_principal is not None:
            clauses.append("json_extract(event_json, '$.enforcing_principal') = ?")
            params.append(enforcing_principal)
        if subject_token_verified is not None:
            clauses.append("subject_token_verified = ?")
            params.append(1 if subject_token_verified else 0)

        sql = (
            "SELECT event_json FROM audit_events "
            f"WHERE {' AND '.join(clauses)} "
            "ORDER BY seq DESC"
        )
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)

        rows = self._conn.execute(sql, tuple(params)).fetchall()
        # rows are most-recent-first; return oldest-first within the window to
        # match the legacy insertion-ordered `[-limit:]` output.
        return tuple(_audit_event_from_json(row[0]) for row in reversed(rows))

    # EVERY materialized audit_events column that mirrors an event_json field —
    # cross-checked against the canonical JSON during verify_chain so a DB-write
    # attacker cannot skew what filters/readers see without breaking verification.
    # MUST stay identical to PostgresAuditWriter._CROSSCHECK_COLUMNS — a parity
    # test (tests/test_audit_hash_chain_sqlite.py) guards against drift.
    _CROSSCHECK_COLUMNS = (
        "event_id", "event_type", "decision", "reason", "workspace_id", "agent_id",
        "grant_id", "grant_ref", "action", "resource", "scope_attempted",
        "scope_matched", "boundary_id", "runtime", "boundary_type", "created_at",
        "subject_token_verified", "event_class",
    )

    def verify_chain(self) -> ChainVerification:
        rows = self._conn.execute(
            "SELECT seq, prev_hash, row_hash, event_json, "
            + ", ".join(self._CROSSCHECK_COLUMNS)
            + " FROM audit_events ORDER BY seq"
        ).fetchall()
        prev = GENESIS_PREV_HASH
        expected_seq = 1
        head_seq, head_hash = 0, GENESIS_PREV_HASH
        for row in rows:
            seq, prev_hash, stored_hash, event_json = row[0], row[1], row[2], row[3]
            cols = row[4:]
            event_id = cols[0]
            if seq != expected_seq:
                return ChainVerification(
                    False, len(rows), head_seq, head_hash,
                    break_seq=expected_seq, break_event_id=event_id, break_kind="deleted",
                )
            if prev_hash != prev:
                return ChainVerification(
                    False, len(rows), head_seq, head_hash,
                    break_seq=seq, break_event_id=event_id, break_kind="reordered",
                )
            if stored_hash != row_hash(seq, event_json, prev_hash):
                return ChainVerification(
                    False, len(rows), head_seq, head_hash,
                    break_seq=seq, break_event_id=event_id, break_kind="modified",
                )
            data = json.loads(event_json)
            for name, value in zip(self._CROSSCHECK_COLUMNS, cols, strict=False):
                if not crosscheck_values_match(name, event_json_value(data, name), value):
                    return ChainVerification(
                        False, len(rows), head_seq, head_hash,
                        break_seq=seq, break_event_id=event_id,
                        break_kind="column_mismatch",
                    )
            prev = stored_hash
            head_seq, head_hash = seq, stored_hash
            expected_seq += 1
        return ChainVerification(True, len(rows), head_seq, head_hash)

    def chain_head(self) -> tuple[int, str]:
        row = self._conn.execute(
            "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return (row[0], row[1]) if row else (0, GENESIS_PREV_HASH)

    def verify_against_anchor(self, records: list[AnchorRecord]) -> AnchorVerification:
        # `records` MUST be a concrete sequence (list/tuple), not a generator, so
        # `len(records)` is correct after the loop.
        covered = 0
        for rec in records:
            row = self._conn.execute(
                "SELECT row_hash FROM audit_events WHERE seq = ?", (rec.seq,)
            ).fetchone()
            if row is None:
                return AnchorVerification(
                    False, covered, covered, divergence_seq=rec.seq, divergence_kind="missing"
                )
            if row[0] != rec.row_hash:
                return AnchorVerification(
                    False, covered, covered, divergence_seq=rec.seq, divergence_kind="mismatch"
                )
            covered = max(covered, rec.seq)
        return AnchorVerification(True, len(records), covered)


def _boundary_control_operation(operation: str) -> tuple[str, str]:
    if operation == "register":
        return EVENT_BOUNDARY_REGISTERED, "register_boundary"
    if operation == "enable":
        return EVENT_BOUNDARY_STATUS_CHANGED, "enable_boundary"
    if operation == "disable":
        return EVENT_BOUNDARY_STATUS_CHANGED, "disable_boundary"
    raise ValueError(f"unknown boundary operation: {operation}")


class SQLiteBoundaryRegistry:
    def __init__(
        self, conn: sqlite3.Connection, control_auditor: ControlPlaneAuditor
    ) -> None:
        self._conn = require_serialized(conn)
        control_auditor.require_bound_to(self._conn)
        self._control_auditor = control_auditor

    def add(self, boundary: Boundary, *, operation: str = "register") -> Boundary:
        event_type, action = _boundary_control_operation(operation)
        with _atomic_write(self._conn):
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
            self._control_auditor.record(
                event_type=event_type,
                workspace_id=boundary.workspace_id,
                action=action,
                resource=f"boundary/{boundary.boundary_id}",
                reason=f"status={boundary.status}",
                boundary_id=boundary.boundary_id,
                now=boundary.updated_at,
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


@dataclass(frozen=True)
class SQLiteServiceSharedState:
    """Process-local collaborators shared by every pooled SQLite service."""

    auth_failures: AuthFailureAuditThrottle
    audit_anchor: AuditAnchor
    audit_export: AuditExport


@dataclass
class SQLiteV1Service:
    conn: sqlite3.Connection
    initialize_schema: bool = True
    shared_state: SQLiteServiceSharedState | None = None
    grant_repository: SQLiteGrantRepository = field(init=False)
    audit_writer: SQLiteAuditWriter = field(init=False)
    control_auditor: ControlPlaneAuditor = field(init=False)
    boundary_registry: SQLiteBoundaryRegistry = field(init=False)
    scope_bounds_repository: SQLiteAgentIssuableScopeBoundsRepository = field(init=False)
    grant_request_repository: SQLiteGrantRequestRepository = field(init=False)
    auto_approval_rule_repository: SQLiteAutoApprovalRuleRepository = field(init=False)
    subject_token_repository: SQLiteSubjectTokenRepository = field(init=False)
    agent_enforcement_settings_repository: SQLiteAgentEnforcementSettingsRepository = field(
        init=False
    )
    _auth_failures: AuthFailureAuditThrottle = field(init=False)
    _POOL_FIELD_CLASSIFICATIONS: ClassVar[dict[str, str]] = {
        "conn": "connection",
        "initialize_schema": "configuration",
        "shared_state": "process_shared",
        "grant_repository": "database_backed",
        "audit_writer": "connection_writer_with_shared_sinks",
        "control_auditor": "connection_writer_with_shared_sinks",
        "boundary_registry": "database_backed",
        "scope_bounds_repository": "database_backed",
        "grant_request_repository": "database_backed",
        "auto_approval_rule_repository": "database_backed",
        "subject_token_repository": "database_backed",
        "agent_enforcement_settings_repository": "database_backed",
        "_auth_failures": "process_shared_alias",
        "_pop_replay": "database_backed",
    }

    def __post_init__(self) -> None:
        # Every repository shares this one connection across the threaded HTTP
        # runtime, so it must be serialized — and by exactly ONE wrapper. The
        # service requires an already-serialized connection (from connect_sqlite,
        # the single raw-opener) rather than wrapping raw itself, so two services
        # on one physical connection cannot mint two independent locks. The same
        # wrapper is handed to every repository below.
        self.conn = require_serialized(self.conn)
        if self.initialize_schema:
            init_sqlite_schema(self.conn)
        self.grant_repository = SQLiteGrantRepository(self.conn)
        import os
        if self.shared_state is None:
            self.shared_state = SQLiteServiceSharedState(
                auth_failures=AuthFailureAuditThrottle(),
                audit_anchor=anchor_from_env(dict(os.environ)),
                audit_export=audit_export_from_env(dict(os.environ)),
            )
        shared_state = self.shared_state
        self.audit_writer = SQLiteAuditWriter(
            self.conn, anchor=shared_state.audit_anchor
        )
        # Opt-in SIEM/OTel export (VINCTOR_AUDIT_EXPORT): when unset the writer
        # above is used as-is; when set it is wrapped so each persisted event is
        # ALSO streamed, fail-open, after the durable write.
        export = shared_state.audit_export
        if not isinstance(export, NullExport):
            self.audit_writer = ExportingAuditWriter(self.audit_writer, export)
        # Control-plane mutations audit through the SAME (possibly
        # export-wrapped) writer as decisions: one chain, one clock (ADR 0019).
        self.control_auditor = ControlPlaneAuditor(self.audit_writer)
        self._auth_failures = shared_state.auth_failures
        self.boundary_registry = SQLiteBoundaryRegistry(
            self.conn, self.control_auditor
        )
        self.scope_bounds_repository = SQLiteAgentIssuableScopeBoundsRepository(
            self.conn, self.control_auditor
        )
        self.grant_request_repository = SQLiteGrantRequestRepository(self.conn)
        self.auto_approval_rule_repository = SQLiteAutoApprovalRuleRepository(
            self.conn, self.control_auditor
        )
        self.subject_token_repository = SQLiteSubjectTokenRepository(self.conn)
        self.agent_enforcement_settings_repository = SQLiteAgentEnforcementSettingsRepository(
            self.conn, self.control_auditor
        )
        self._pop_replay = SQLiteReplayStore(self.conn)

    def assert_pool_state_contract(self) -> None:
        """Fail when new service instance state lacks an explicit pool policy."""
        expected = set(self._POOL_FIELD_CLASSIFICATIONS)
        actual = set(vars(self))
        if actual != expected:
            undeclared = sorted(actual - expected)
            missing = sorted(expected - actual)
            raise RuntimeError(
                "SQLiteV1Service pooled-state contract drifted: "
                f"undeclared={undeclared}, missing={missing}"
            )

    def insert_grant(self, grant: Grant) -> None:
        insert_grant(self.conn, grant)

    def schema_versions(self) -> tuple[int, ...]:
        return get_sqlite_schema_versions(self.conn)

    def set_agent_issuable_scope_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        now: datetime,
    ) -> None:
        self.scope_bounds_repository.set_bounds(
            workspace_id=workspace_id,
            agent_id=agent_id,
            scopes=scopes,
            max_ttl_seconds=max_ttl_seconds,
            now=now,
        )

    def issue_grant(
        self,
        request: GrantIssueRequest,
        *,
        now: datetime,
    ) -> GrantIssueResult:
        with _atomic_write(self.conn):
            return issue_grant(
                request,
                grant_repository=self.grant_repository,
                scope_bounds_repository=self.scope_bounds_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def lookup_grant(self, *, grant_ref: str, workspace_id: str) -> Grant | None:
        return lookup_grant(
            grant_ref=grant_ref,
            workspace_id=workspace_id,
            grant_repository=self.grant_repository,
        )

    def list_grants(
        self,
        *,
        workspace_id: str,
        agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]:
        return list_grants(
            workspace_id=workspace_id,
            agent_id=agent_id,
            status=status,
            grant_repository=self.grant_repository,
        )

    def revoke_grant(
        self,
        *,
        grant_ref: str,
        workspace_id: str,
        now: datetime,
    ) -> tuple[Grant, str] | None:
        with _atomic_write(self.conn):
            return revoke_grant(
                grant_ref=grant_ref,
                workspace_id=workspace_id,
                grant_repository=self.grant_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def create_grant_request(
        self,
        request: GrantRequestCreateRequest,
        *,
        now: datetime,
    ) -> GrantRequestCreateResult:
        with _atomic_write(self.conn):
            return create_grant_request(
                request,
                request_repository=self.grant_request_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def mint_subject_token(
        self, *, workspace_id, agent_id, grant_ref, audience, ttl_seconds, now,
        bound_action=None, bound_resource=None, pop=False,
    ):
        # Only the SUCCESSFUL mint's state+audit pair is wrapped in _atomic_write
        # (injected via ``atomic``); the FORBIDDEN path writes its best-effort
        # rejection audit standalone, exactly like the enforce/simulate rejection
        # audits — so a forbidden probe opens no fallible outer commit and its
        # audit failure never changes the generic forbidden result.
        return mint_subject_token(
            grant_repository=self.grant_repository,
            subject_token_repository=self.subject_token_repository,
            audit_writer=self.audit_writer,
            workspace_id=workspace_id, agent_id=agent_id, grant_ref=grant_ref,
            audience=audience, ttl_seconds=ttl_seconds, now=now,
            bound_action=bound_action, bound_resource=bound_resource, pop=pop,
            atomic=lambda: _atomic_write(self.conn),
        )

    def lookup_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
    ) -> GrantRequest | None:
        return lookup_grant_request(
            request_id=request_id,
            workspace_id=workspace_id,
            request_repository=self.grant_request_repository,
        )

    def list_grant_requests(self, *, workspace_id: str) -> tuple[GrantRequest, ...]:
        return list_grant_requests(
            workspace_id=workspace_id,
            request_repository=self.grant_request_repository,
        )

    def approve_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        decision_reason: str | None,
        now: datetime,
    ) -> GrantRequestDecisionResult:
        with _atomic_write(self.conn):
            return approve_grant_request(
                request_id=request_id,
                workspace_id=workspace_id,
                decided_by=decided_by,
                decision_reason=decision_reason,
                request_repository=self.grant_request_repository,
                grant_repository=self.grant_repository,
                scope_bounds_repository=self.scope_bounds_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def reject_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        decision_reason: str | None,
        now: datetime,
    ) -> GrantRequestDecisionResult:
        with _atomic_write(self.conn):
            return reject_grant_request(
                request_id=request_id,
                workspace_id=workspace_id,
                decided_by=decided_by,
                decision_reason=decision_reason,
                request_repository=self.grant_request_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def create_auto_approval_rule(self, rule: AutoApprovalRule) -> AutoApprovalRule:
        return create_auto_approval_rule(
            rule_repository=self.auto_approval_rule_repository,
            rule=rule,
        )

    def list_auto_approval_rules(self, *, workspace_id: str) -> tuple[AutoApprovalRule, ...]:
        return list_auto_approval_rules(
            rule_repository=self.auto_approval_rule_repository,
            workspace_id=workspace_id,
        )

    def disable_auto_approval_rule(
        self,
        *,
        rule_id: str,
        workspace_id: str,
        disabled_by: str,
        now: datetime,
    ) -> AutoApprovalRule | None:
        return disable_auto_approval_rule(
            rule_repository=self.auto_approval_rule_repository,
            rule_id=rule_id,
            workspace_id=workspace_id,
            disabled_by=disabled_by,
            now=now,
        )

    def evaluate_auto_approval(
        self,
        *,
        request: GrantRequest,
    ) -> AutoApprovalEvaluationResult:
        return evaluate_auto_approval(
            request=request,
            rule_repository=self.auto_approval_rule_repository,
        )

    def auto_approve_grant_request(
        self,
        *,
        request_id: str,
        workspace_id: str,
        decided_by: str,
        now: datetime,
    ) -> GrantRequestDecisionResult:
        with _atomic_write(self.conn):
            return auto_approve_grant_request(
                request_id=request_id,
                workspace_id=workspace_id,
                decided_by=decided_by,
                request_repository=self.grant_request_repository,
                rule_repository=self.auto_approval_rule_repository,
                grant_repository=self.grant_repository,
                scope_bounds_repository=self.scope_bounds_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self.audit_writer.list_all())

    def get_audit_event(self, event_id: str) -> AuditEvent | None:
        return self.audit_writer.get(event_id)

    def list_auth_failures(self, *, limit: int) -> tuple[AuditEvent, ...]:
        return self.audit_writer.list_auth_failures(limit=limit)

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
        subject_token_verified: bool | None = None,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        return self.audit_writer.list_filtered(
            workspace_id,
            event_type=event_type,
            grant_ref=grant_ref,
            boundary_id=boundary_id,
            agent_id=agent_id,
            request_id=request_id,
            reason_code=reason_code,
            enforcing_principal=enforcing_principal,
            subject_token_verified=subject_token_verified,
            limit=limit,
        )

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

    def record_auth_failure(self, *, surface: str, now: datetime) -> None:
        self._auth_failures.record(self.audit_writer, surface=surface, now=now)

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
            agent_enforcement_settings_repository=self.agent_enforcement_settings_repository,
        )

    def observe(self, request: V1ObserveRequest, *, now: datetime) -> V1ObserveResponse:
        return record_observation(
            request,
            audit_writer=self.audit_writer,
            now=now,
            boundary_registry=self.boundary_registry,
        )

    def simulate(self, request: V1SimulateRequest, *, now: datetime) -> V1SimulateResponse:
        return simulate_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
            agent_enforcement_settings_repository=self.agent_enforcement_settings_repository,
        )

    def delegated_enforce(
        self,
        request: V1DelegatedEnforceRequest,
        *,
        now: datetime,
        pep_workspace_id: str | None = None,
        pop_skew_seconds: int = DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS,
    ) -> V1EnforceResponse:
        # ``pep_workspace_id`` is the TRUSTED workspace derived from the
        # authenticated PEP key (see handle_v1_delegated_enforce_http). Without
        # it the contract fails closed.
        return delegated_enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
            pep_workspace_id=pep_workspace_id,
            subject_token_repository=self.subject_token_repository,
            agent_enforcement_settings_repository=self.agent_enforcement_settings_repository,
            pop_replay_cache=self._pop_replay,
            pop_skew_seconds=pop_skew_seconds,
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


def _grant_from_row(row: sqlite3.Row | tuple[object, ...]) -> Grant:
    expires_at = _datetime_from_storage(row[6])
    # Defense-in-depth: coerce a tz-naive expires_at to UTC so the enforce
    # comparison against a tz-aware ``now`` cannot raise TypeError (it already
    # fails closed on error, but we normalize rather than rely on that).
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return Grant(
        grant_id=row[0],
        grant_ref=row[1],
        workspace_id=row[2],
        agent_id=row[3],
        scopes=tuple(json.loads(row[4])),
        status=row[5],
        expires_at=expires_at,
    )


def _grant_request_values(request: GrantRequest) -> tuple[object, ...]:
    return (
        request.request_id,
        request.workspace_id,
        request.requester_agent_id,
        request.target_agent_id,
        json.dumps(list(request.requested_scopes)),
        request.requested_ttl_seconds,
        request.reason,
        request.status,
        request.created_at.isoformat(),
        _datetime_to_storage(request.decided_at),
        request.decided_by,
        request.decision_reason,
        request.issued_grant_ref,
        request.task_id,
        request.session_id,
        request.boundary_id,
        request.requester_runtime,
        request.repo,
        request.worktree,
    )


def _grant_request_from_row(row: sqlite3.Row | tuple | None) -> GrantRequest | None:
    if row is None:
        return None
    return GrantRequest(
        request_id=row[0],
        workspace_id=row[1],
        requester_agent_id=row[2],
        target_agent_id=row[3],
        requested_scopes=tuple(json.loads(row[4])),
        requested_ttl_seconds=row[5],
        reason=row[6],
        status=row[7],
        created_at=datetime.fromisoformat(row[8]),
        decided_at=_datetime_from_storage(row[9]),
        decided_by=row[10],
        decision_reason=row[11],
        issued_grant_ref=row[12],
        task_id=row[13],
        session_id=row[14],
        boundary_id=row[15],
        requester_runtime=row[16],
        repo=row[17],
        worktree=row[18],
    )


def _subject_token_from_row(row: sqlite3.Row | tuple | None) -> SubjectToken | None:
    if row is None:
        return None
    # pop_secret is only selected by get_by_hash (verification needs it); list/get_by_id
    # omit it (12-column rows) so it never reaches operator surfaces. Default to None.
    pop_secret = row[12] if len(row) > 12 else None
    return SubjectToken(
        token_id=row[0],
        token_hash=row[1],
        workspace_id=row[2],
        agent_id=row[3],
        grant_ref=row[4],
        audience=row[5],
        issued_at=datetime.fromisoformat(row[6]),
        expires_at=datetime.fromisoformat(row[7]),
        created_by=row[8],
        revoked_at=_datetime_from_storage(row[9]),
        bound_action=row[10],
        bound_resource=row[11],
        pop_secret=pop_secret,
    )


def _auto_approval_rule_values(rule: AutoApprovalRule) -> tuple[object, ...]:
    return (
        rule.rule_id,
        rule.workspace_id,
        rule.name,
        rule.target_agent_id,
        json.dumps(list(rule.allowed_scopes)),
        rule.max_ttl_seconds,
        rule.status,
        rule.created_by,
        rule.created_at.isoformat(),
        rule.updated_by,
        _datetime_to_storage(rule.updated_at),
    )


def _auto_approval_rule_from_row(
    row: sqlite3.Row | tuple | None,
) -> AutoApprovalRule | None:
    if row is None:
        return None
    return AutoApprovalRule(
        rule_id=row[0],
        workspace_id=row[1],
        name=row[2],
        target_agent_id=row[3],
        allowed_scopes=tuple(json.loads(row[4])),
        max_ttl_seconds=row[5],
        status=row[6],
        created_by=row[7],
        created_at=datetime.fromisoformat(row[8]),
        updated_by=row[9],
        updated_at=_datetime_from_storage(row[10]),
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
        subject_token_verified=subject_token_verified_from_json(data),
        token_id=data.get("token_id"),
        event_class=data.get("event_class", "decision"),
    )


def _optional_datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None
