from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from vinctor_core import (
    disable_boundary,
    enable_boundary,
    get_boundary_for_workspace,
    register_boundary,
)
from vinctor_core.models import AuditEvent, Boundary, BoundaryRegistrationInput, Grant
from vinctor_service.audit import AuthFailureAuditThrottle
from vinctor_service.auto_approval import (
    auto_approve_grant_request,
    create_auto_approval_rule,
    disable_auto_approval_rule,
    evaluate_auto_approval,
    list_auto_approval_rules,
)
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
)
from vinctor_service.service_config import DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS
from vinctor_service.subject_tokens import mint_subject_token
from vinctor_service.v1_enforce import delegated_enforce_v1_contract, enforce_v1_contract


def init_sqlite_schema(conn: sqlite3.Connection) -> None:
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
            require_subject_token INTEGER NOT NULL DEFAULT 0,
            require_pop INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (workspace_id, agent_id)
        );

        CREATE TABLE IF NOT EXISTS pop_replay_nonces (
            token_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ts INTEGER NOT NULL,
            PRIMARY KEY (token_id, nonce)
        );
        CREATE INDEX IF NOT EXISTS idx_pop_replay_nonces_ts
        ON pop_replay_nonces(ts);
        """
    )
    _ensure_grant_request_metadata_columns(conn)
    _ensure_scope_bounds_max_ttl_column(conn)
    _ensure_subject_tokens_revoked_at_column(conn)
    _ensure_subject_tokens_bound_columns(conn)
    _ensure_subject_tokens_pop_secret_column(conn)
    _ensure_agent_enforcement_require_subject_token_column(conn)
    _ensure_agent_enforcement_require_pop_column(conn)
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

        with self._conn:
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


class SQLiteAgentIssuableScopeBoundsRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

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
        with self._conn:
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


class SQLiteAgentEnforcementSettingsRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

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
            WHERE workspace_id = ? AND agent_id = ?
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
            WHERE workspace_id = ?
            ORDER BY agent_id
            """,
            (workspace_id,),
        ).fetchall()
        return tuple((row[0], bool(row[1])) for row in rows)

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, require_boundary, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    require_boundary = excluded.require_boundary,
                    updated_at = excluded.updated_at
                """,
                (workspace_id, agent_id, 1 if require_boundary else 0, now.isoformat()),
            )

    def get_require_subject_token_setting(
        self, *, workspace_id: str, agent_id: str
    ) -> bool | None:
        row = self._conn.execute(
            """
            SELECT require_subject_token FROM agent_enforcement_settings
            WHERE workspace_id = ? AND agent_id = ?
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
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, require_subject_token, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    require_subject_token = excluded.require_subject_token,
                    updated_at = excluded.updated_at
                """,
                (workspace_id, agent_id, 1 if require_subject_token else 0, now.isoformat()),
            )

    def get_require_pop_setting(self, *, workspace_id: str, agent_id: str) -> bool | None:
        row = self._conn.execute(
            """
            SELECT require_pop FROM agent_enforcement_settings
            WHERE workspace_id = ? AND agent_id = ?
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
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, require_pop, updated_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(workspace_id, agent_id) DO UPDATE SET
                    require_pop = excluded.require_pop,
                    updated_at = excluded.updated_at
                """,
                (workspace_id, agent_id, 1 if require_pop else 0, now.isoformat()),
            )


class SQLiteGrantRequestRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def insert_request(self, request: GrantRequest) -> None:
        if self.get_request(request.request_id) is not None:
            raise ValueError(f"duplicate grant request_id: {request.request_id}")
        with self._conn:
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
        with self._conn:
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

    def __init__(self, conn: sqlite3.Connection, max_entries: int = 10000) -> None:
        self._conn = conn
        self._max = max_entries
        # The live SQLite service shares ONE connection (check_same_thread=False)
        # across ThreadingHTTPServer threads; serialize the multi-statement
        # transaction within-process. The PK + IntegrityError covers cross-process
        # / cross-thread races that slip past the lock.
        self._lock = threading.Lock()

    def check_and_record(
        self, *, token_id: str, nonce: str, ts: int, now_unix: int, skew: int
    ) -> bool:
        cutoff = now_unix - skew
        with self._lock, self._conn:
            self._conn.execute(
                "DELETE FROM pop_replay_nonces WHERE ts < ?", (cutoff,)
            )
            row = self._conn.execute(
                "SELECT 1 FROM pop_replay_nonces WHERE token_id = ? AND nonce = ?",
                (token_id, nonce),
            ).fetchone()
            if row is not None:
                return False  # replay
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
        self._conn = conn

    def insert(self, token: SubjectToken) -> None:
        if self.get_by_hash(token.token_hash) is not None:
            raise ValueError(f"duplicate subject token_hash: {token.token_hash}")
        with self._conn:
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
        with self._conn:
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
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def add_rule(self, rule: AutoApprovalRule) -> None:
        if self.get_rule(rule.rule_id) is not None:
            raise ValueError(f"duplicate auto-approval rule_id: {rule.rule_id}")
        with self._conn:
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
        with self._conn:
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
    scope_bounds_repository: SQLiteAgentIssuableScopeBoundsRepository = field(init=False)
    grant_request_repository: SQLiteGrantRequestRepository = field(init=False)
    auto_approval_rule_repository: SQLiteAutoApprovalRuleRepository = field(init=False)
    subject_token_repository: SQLiteSubjectTokenRepository = field(init=False)
    agent_enforcement_settings_repository: SQLiteAgentEnforcementSettingsRepository = field(
        init=False
    )
    _auth_failures: AuthFailureAuditThrottle = field(init=False)

    def __post_init__(self) -> None:
        if self.initialize_schema:
            init_sqlite_schema(self.conn)
        self.grant_repository = SQLiteGrantRepository(self.conn)
        self.audit_writer = SQLiteAuditWriter(self.conn)
        self._auth_failures = AuthFailureAuditThrottle()
        self.boundary_registry = SQLiteBoundaryRegistry(self.conn)
        self.scope_bounds_repository = SQLiteAgentIssuableScopeBoundsRepository(self.conn)
        self.grant_request_repository = SQLiteGrantRequestRepository(self.conn)
        self.auto_approval_rule_repository = SQLiteAutoApprovalRuleRepository(self.conn)
        self.subject_token_repository = SQLiteSubjectTokenRepository(self.conn)
        self.agent_enforcement_settings_repository = SQLiteAgentEnforcementSettingsRepository(
            self.conn
        )
        self._pop_replay = SQLiteReplayStore(self.conn)

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
        return mint_subject_token(
            grant_repository=self.grant_repository,
            subject_token_repository=self.subject_token_repository,
            audit_writer=self.audit_writer,
            workspace_id=workspace_id, agent_id=agent_id, grant_ref=grant_ref,
            audience=audience, ttl_seconds=ttl_seconds, now=now,
            bound_action=bound_action, bound_resource=bound_resource, pop=pop,
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

    def record_auth_failure(
        self, *, surface: str, boundary_id: str | None, now: datetime
    ) -> None:
        self._auth_failures.record(
            self.audit_writer, surface=surface, boundary_id=boundary_id, now=now
        )

    def enforce(self, request: V1EnforceRequest, *, now: datetime) -> V1EnforceResponse:
        return enforce_v1_contract(
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
        pop_skew_seconds: int = DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS,
    ) -> V1EnforceResponse:
        return delegated_enforce_v1_contract(
            request,
            grant_repository=self.grant_repository,
            now=now,
            audit_writer=self.audit_writer,
            boundary_registry=self.boundary_registry,
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
    return Grant(
        grant_id=row[0],
        grant_ref=row[1],
        workspace_id=row[2],
        agent_id=row[3],
        scopes=tuple(json.loads(row[4])),
        status=row[5],
        expires_at=_datetime_from_storage(row[6]),
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
        identity_proven=data.get("identity_proven", False),
        token_id=data.get("token_id"),
    )
