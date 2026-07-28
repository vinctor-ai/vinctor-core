from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from typing import Any

from vinctor_core import (
    disable_boundary,
    enable_boundary,
    get_boundary_for_workspace,
    register_boundary,
)
from vinctor_core.audit import (
    EVENT_AUTO_APPROVAL_RULE_CREATED,
    EVENT_BOUNDARY_REGISTERED,
    EVENT_BOUNDARY_STATUS_CHANGED,
    EVENT_ENFORCEMENT_SETTING_CHANGED,
    EVENT_SCOPE_BOUNDS_SET,
    validate_audit_event_class,
)
from vinctor_core.models import AuditEvent, Boundary, BoundaryRegistrationInput, Grant
from vinctor_service.audit import AuthFailureAuditThrottle, InvalidAuditCursorError
from vinctor_service.audit_anchor import AuditAnchor, NullAnchor
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
    ExportingAuditWriter,
    NullExport,
)
from vinctor_service.audit_sink import audit_sinks_from_env
from vinctor_service.auto_approval import (
    auto_approval_update_control_event,
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
    set_bounds_audit_reason,
    validate_clear_max_ttl,
    validate_issuable_scope_bounds,
)
from vinctor_service.idempotency_keyring import (
    IdempotencyKeyring,
    validate_startup_compatibility,
)
from vinctor_service.idempotency_lifecycle_postgres_lock import (
    PostgresWriterAttestation,
)
from vinctor_service.idempotency_models import (
    IdempotencyInvocation,
    IdempotencyKeyCommitment,
    IdempotencyKeyRegistration,
    IdempotencyKeyringConfigError,
    IdempotencyKeyVersionLabel,
    IdempotencyMutation,
    PreSerializedHttpResponse,
)
from vinctor_service.idempotency_postgres import (
    PostgresIdempotencyStore,
    PostgresIdempotentMutationExecutor,
)
from vinctor_service.idempotency_readiness import postgres_idempotency_ready
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
    V1DelegatedEnforceRequest,
    V1EnforceRequest,
    V1EnforceResponse,
    V1ObserveRequest,
    V1ObserveResponse,
    V1SimulateRequest,
    V1SimulateResponse,
)
from vinctor_service.observations import record_observation
from vinctor_service.postgres_connection import (
    SerializedPostgresConnection as SerializedPostgresConnection,
)
from vinctor_service.postgres_connection import connect_postgres as connect_postgres
from vinctor_service.postgres_connection import (
    connect_postgres_readiness as connect_postgres_readiness,
)
from vinctor_service.postgres_control import (
    PostgresGrantRequestRepository,
    PostgresReplayStore,
    PostgresSubjectTokenRepository,
)
from vinctor_service.postgres_driver import UniqueViolation
from vinctor_service.service_config import DEFAULT_SUBJECT_TOKEN_POP_SKEW_SECONDS
from vinctor_service.simulations import simulate_v1_contract

# The shared checker raises SchemaVersionError on both backends, so callers
# (the CLI startup path) handle a too-new database uniformly.
from vinctor_service.sqlite import _assert_schema_not_newer
from vinctor_service.subject_tokens import mint_subject_token
from vinctor_service.v1_enforce import delegated_enforce_v1_contract, enforce_v1_contract

AUDIT_CHAIN_LOCK_ID = 0x56494E43
# Two-key advisory-lock class for serializing grant-request decisions per
# request (pg_advisory_xact_lock(classid, key)). Same pattern as the policy
# apply lock in postgres_policy, in a distinct classid keyspace.
GRANT_REQUEST_DECISION_LOCK_CLASSID = 0x56475244


def _grant_request_decision_lock_key(request_id: str) -> int:
    """Stable non-negative int4 advisory-lock key derived from the request."""
    digest = hashlib.sha256(request_id.encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") & 0x7FFFFFFF


@contextmanager
def _grant_request_decision_transaction(conn: Any, request_id: str) -> Iterator[None]:
    """One transaction for a whole grant-request decision, serialized per request.

    Takes a request-scoped ``pg_advisory_xact_lock`` up front so concurrent
    deciders of the same request queue instead of interleaving; the pending
    check, the compare-and-set claim, the grant issuance, and the audit rows
    then commit together or roll back together (the repositories' nested
    ``transaction()`` scopes become savepoints under this outer transaction).
    The lock is transaction-scoped and releases at commit/rollback.
    """
    with conn.transaction():
        conn.execute(
            "SELECT pg_advisory_xact_lock(%s::int4, %s::int4)",
            (
                GRANT_REQUEST_DECISION_LOCK_CLASSID,
                _grant_request_decision_lock_key(request_id),
            ),
        )
        yield


def _postgres_column_exists(conn: Any, table_name: str, column_name: str) -> bool:
    row = conn.execute(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = %s AND column_name = %s
        """,
        (table_name, column_name),
    ).fetchone()
    return row is not None


# Highest schema version this binary knows how to create or migrate to (PKA-40).
# _POSTGRES_SCHEMA_VERSIONS below derives from it and is what init_postgres_schema
# records, so the constant cannot drift from the recorded versions; the CI-only
# drift guard in tests/test_storage_ops.py pins the pairing against a live
# database as well.
POSTGRES_SCHEMA_VERSION_MAX = 8
_POSTGRES_SCHEMA_VERSIONS = tuple(range(1, POSTGRES_SCHEMA_VERSION_MAX + 1))


def _assert_postgres_schema_supported(conn: Any) -> None:
    """Refuse a database stamped by a newer binary, before touching its schema."""
    table = conn.execute(
        """
        SELECT 1 FROM information_schema.tables
        WHERE table_schema = current_schema() AND table_name = 'schema_migrations'
        """
    ).fetchone()
    if table is None:
        return
    row = conn.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
    _assert_schema_not_newer(
        row[0] if row is not None else None,
        POSTGRES_SCHEMA_VERSION_MAX,
        backend="Postgres",
    )


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
            subject_token_verified BOOLEAN NOT NULL DEFAULT FALSE,
            token_id TEXT,
            event_class TEXT NOT NULL DEFAULT 'decision',
            event_json TEXT NOT NULL,
            seq BIGINT NOT NULL UNIQUE,
            prev_hash TEXT NOT NULL,
            row_hash TEXT NOT NULL
        )
        """,
        """
        ALTER TABLE audit_events
        ADD COLUMN IF NOT EXISTS event_class TEXT NOT NULL DEFAULT 'decision'
        """,
        """
        ALTER TABLE audit_events
        ADD COLUMN IF NOT EXISTS subject_token_verified BOOLEAN NOT NULL DEFAULT FALSE
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_audit_workspace_seq
        ON audit_events(workspace_id, seq DESC)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_audit_agent
        ON audit_events(workspace_id, agent_id, seq DESC)
        """,
        """
        CREATE TABLE IF NOT EXISTS boundaries (
            boundary_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            name TEXT NOT NULL,
            runtime TEXT NOT NULL,
            boundary_type TEXT NOT NULL,
            mode TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL,
            UNIQUE (workspace_id, name)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_boundaries_workspace
        ON boundaries(workspace_id, created_at, boundary_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_enforcement_settings (
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            require_boundary BOOLEAN NOT NULL DEFAULT TRUE,
            require_boundary_set BOOLEAN NOT NULL DEFAULT FALSE,
            require_subject_token BOOLEAN NOT NULL DEFAULT FALSE,
            require_subject_token_set BOOLEAN NOT NULL DEFAULT FALSE,
            require_pop BOOLEAN NOT NULL DEFAULT FALSE,
            require_pop_set BOOLEAN NOT NULL DEFAULT FALSE,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (workspace_id, agent_id)
        )
        """,
        """
        ALTER TABLE agent_enforcement_settings
        ADD COLUMN IF NOT EXISTS require_boundary_set BOOLEAN NOT NULL DEFAULT TRUE
        """,
        """
        ALTER TABLE agent_enforcement_settings
        ADD COLUMN IF NOT EXISTS require_subject_token_set BOOLEAN NOT NULL DEFAULT FALSE
        """,
        """
        ALTER TABLE agent_enforcement_settings
        ADD COLUMN IF NOT EXISTS require_pop_set BOOLEAN NOT NULL DEFAULT FALSE
        """,
        """
        CREATE TABLE IF NOT EXISTS agent_issuable_scope_bounds (
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            scopes_json JSONB NOT NULL,
            max_ttl_seconds INTEGER,
            updated_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (workspace_id, agent_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS auto_approval_rules (
            rule_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            name TEXT NOT NULL,
            target_agent_id TEXT NOT NULL,
            allowed_scopes_json JSONB NOT NULL,
            max_ttl_seconds INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_by TEXT,
            updated_at TIMESTAMPTZ
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_auto_approval_workspace
        ON auto_approval_rules(workspace_id, created_at, rule_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS local_keys (
            key_id TEXT PRIMARY KEY,
            key_type TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            agent_id TEXT,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            last_used_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_local_keys_workspace
        ON local_keys(workspace_id, created_at, key_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS grant_requests (
            request_id TEXT PRIMARY KEY,
            workspace_id TEXT NOT NULL,
            requester_agent_id TEXT NOT NULL,
            target_agent_id TEXT NOT NULL,
            requested_scopes_json JSONB NOT NULL,
            requested_ttl_seconds INTEGER NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            decided_at TIMESTAMPTZ,
            decided_by TEXT,
            decision_reason TEXT,
            issued_grant_ref TEXT,
            task_id TEXT,
            session_id TEXT,
            boundary_id TEXT,
            requester_runtime TEXT,
            repo TEXT,
            worktree TEXT
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_grant_requests_workspace
        ON grant_requests(workspace_id, created_at, request_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS subject_tokens (
            token_id TEXT PRIMARY KEY,
            token_hash TEXT NOT NULL UNIQUE,
            workspace_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            grant_ref TEXT NOT NULL,
            audience TEXT NOT NULL,
            issued_at TIMESTAMPTZ NOT NULL,
            expires_at TIMESTAMPTZ NOT NULL,
            created_by TEXT NOT NULL,
            revoked_at TIMESTAMPTZ,
            bound_action TEXT,
            bound_resource TEXT,
            pop_secret TEXT
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_subject_tokens_workspace
        ON subject_tokens(workspace_id, issued_at, token_id)
        """,
        """
        CREATE TABLE IF NOT EXISTS pop_replay_nonces (
            token_id TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ts BIGINT NOT NULL,
            PRIMARY KEY (token_id, nonce)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_postgres_pop_replay_ts
        ON pop_replay_nonces(ts)
        """,
        """
        CREATE TABLE IF NOT EXISTS policy_versions (
            workspace_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            action TEXT NOT NULL,
            source_version INTEGER,
            snapshot_json JSONB NOT NULL,
            applied_by TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            PRIMARY KEY (workspace_id, version)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS idempotency_cipher_key_versions (
            version_label TEXT PRIMARY KEY
                CHECK (
                    version_label ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
                ),
            key_commitment BYTEA NOT NULL UNIQUE
                CHECK (octet_length(key_commitment) = 32),
            reserved_encryption_slots BIGINT NOT NULL
                CHECK (reserved_encryption_slots BETWEEN 0 AND 16777216),
            first_seen_epoch BIGINT NOT NULL CHECK (first_seen_epoch >= 0),
            soft_limit_reported_epoch BIGINT
                CHECK (
                    soft_limit_reported_epoch IS NULL
                    OR soft_limit_reported_epoch >= first_seen_epoch
                ),
            write_disabled_epoch BIGINT
                CHECK (
                    write_disabled_epoch IS NULL
                    OR write_disabled_epoch >= first_seen_epoch
                ),
            write_disabled_reason TEXT,
            drain_completed_epoch BIGINT,
            retired_epoch BIGINT,
            CHECK (
                (write_disabled_epoch IS NULL AND write_disabled_reason IS NULL)
                OR (
                    write_disabled_epoch IS NOT NULL
                    AND write_disabled_reason IS NOT NULL
                    AND write_disabled_reason IN ('rotation', 'hard_limit', 'nonce_collision')
                )
            ),
            CHECK (
                drain_completed_epoch IS NULL
                OR (
                    write_disabled_epoch IS NOT NULL
                    AND drain_completed_epoch >= write_disabled_epoch
                )
            ),
            CHECK (
                retired_epoch IS NULL
                OR (
                    drain_completed_epoch IS NOT NULL
                    AND retired_epoch >= drain_completed_epoch
                )
            )
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS idempotency_cipher_nonces (
            cipher_key_version TEXT NOT NULL,
            slot BIGINT NOT NULL CHECK (slot BETWEEN 1 AND 16777216),
            nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
            reserved_at_epoch BIGINT NOT NULL CHECK (reserved_at_epoch >= 0),
            workspace_id TEXT NOT NULL CHECK (octet_length(workspace_id) > 0),
            principal TEXT NOT NULL CHECK (octet_length(principal) > 0),
            operation TEXT NOT NULL CHECK (octet_length(operation) > 0),
            key_hash BYTEA NOT NULL CHECK (octet_length(key_hash) = 32),
            request_fingerprint BYTEA NOT NULL
            CHECK (octet_length(request_fingerprint) = 32),
            claimed_at_epoch BIGINT
                CHECK (
                    claimed_at_epoch IS NULL
                    OR claimed_at_epoch >= reserved_at_epoch
                ),
            PRIMARY KEY (cipher_key_version, nonce),
            UNIQUE (cipher_key_version, slot),
            FOREIGN KEY (cipher_key_version)
                REFERENCES idempotency_cipher_key_versions(version_label)
                ON UPDATE RESTRICT ON DELETE RESTRICT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS idempotency_results (
            workspace_id TEXT NOT NULL CHECK (octet_length(workspace_id) > 0),
            principal TEXT NOT NULL CHECK (octet_length(principal) > 0),
            operation TEXT NOT NULL CHECK (octet_length(operation) > 0),
            key_hash BYTEA NOT NULL CHECK (octet_length(key_hash) = 32),
            request_fingerprint BYTEA NOT NULL
                CHECK (octet_length(request_fingerprint) = 32),
            format_version SMALLINT NOT NULL CHECK (format_version = 1),
            status_code SMALLINT NOT NULL CHECK (status_code BETWEEN 200 AND 499),
            cipher_key_version TEXT NOT NULL,
            response_nonce BYTEA NOT NULL CHECK (octet_length(response_nonce) = 12),
            response_ciphertext BYTEA NOT NULL
                CHECK (octet_length(response_ciphertext) >= 16),
            created_at_epoch BIGINT NOT NULL CHECK (created_at_epoch >= 0),
            expires_at_epoch BIGINT NOT NULL CHECK (expires_at_epoch > created_at_epoch),
            PRIMARY KEY (workspace_id, principal, operation, key_hash),
            UNIQUE (cipher_key_version, response_nonce),
            FOREIGN KEY (cipher_key_version)
                REFERENCES idempotency_cipher_key_versions(version_label)
                ON UPDATE RESTRICT ON DELETE RESTRICT
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_idempotency_cipher_nonces_version
        ON idempotency_cipher_nonces(cipher_key_version)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_idempotency_results_expires_at
        ON idempotency_results(expires_at_epoch)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_idempotency_results_cipher_version_expires
        ON idempotency_results(cipher_key_version, expires_at_epoch)
        """,
    )
    with conn.transaction():
        # Fail closed BEFORE any DDL: an older binary must not touch — let
        # alone write audit hash-chain rows into — a database whose schema a
        # newer binary owns (PKA-40). Raising here rolls the transaction back.
        _assert_postgres_schema_supported(conn)
        legacy_subject_token_verified = _postgres_column_exists(
            conn, "audit_events", "identity_proven"
        )
        current_subject_token_verified = _postgres_column_exists(
            conn, "audit_events", "subject_token_verified"
        )
        if legacy_subject_token_verified and not current_subject_token_verified:
            conn.execute(
                "ALTER TABLE audit_events RENAME COLUMN identity_proven "
                "TO subject_token_verified"
            )
        subject_token_set_missing = not _postgres_column_exists(
            conn, "agent_enforcement_settings", "require_subject_token_set"
        )
        pop_set_missing = not _postgres_column_exists(
            conn, "agent_enforcement_settings", "require_pop_set"
        )
        for statement in statements:
            conn.execute(statement)
        # Fail closed: a migrated row counts as an explicit setting only where
        # its value is already TRUE; a FALSE value becomes "unset" and falls
        # through to the workspace mandate instead of silently exempting the
        # agent. Runs once, when the column is first added (a fresh database
        # has no rows yet, so this is a no-op there).
        if subject_token_set_missing:
            conn.execute(
                """
                UPDATE agent_enforcement_settings
                SET require_subject_token_set = require_subject_token
                """
            )
        if pop_set_missing:
            conn.execute("UPDATE agent_enforcement_settings SET require_pop_set = require_pop")
        claim_column_missing = not _postgres_column_exists(
            conn,
            "idempotency_cipher_nonces",
            "claimed_at_epoch",
        )
        if claim_column_missing:
            conn.execute(
                "ALTER TABLE idempotency_cipher_nonces "
                "ADD COLUMN claimed_at_epoch BIGINT "
                "CHECK (claimed_at_epoch IS NULL "
                "OR claimed_at_epoch >= reserved_at_epoch)"
            )
        if claim_column_missing:
            conn.execute(
                "UPDATE idempotency_cipher_nonces "
                "SET claimed_at_epoch = reserved_at_epoch "
                "WHERE claimed_at_epoch IS NULL"
            )
        # One-time, version-gated realignment (schema version 5). The original
        # require_boundary_set migration defaulted migrated rows to TRUE, so a
        # row that only ever carried require_subject_token / require_pop read
        # as an explicit require_boundary=false override, silently exempting
        # the agent from a workspace-wide boundary mandate. Fail closed: mark
        # boundary "set" only where require_boundary is already TRUE. Gated on
        # the version record (this UPDATE is not idempotent by itself) so an
        # explicit exemption written after the upgrade is never clobbered by a
        # later init.
        realignment_applied = conn.execute(
            "SELECT 1 FROM schema_migrations WHERE version = %s",
            (5,),
        ).fetchone()
        if realignment_applied is None:
            conn.execute(
                """
                UPDATE agent_enforcement_settings
                SET require_boundary_set = require_boundary
                """
            )
        for version in _POSTGRES_SCHEMA_VERSIONS:
            conn.execute(
                """
                INSERT INTO schema_migrations (version, applied_at)
                VALUES (%s, %s)
                ON CONFLICT (version) DO NOTHING
                """,
                (version, datetime.now(UTC)),
            )


def _register_postgres_idempotency_keyring(
    conn: Any,
    keyring: IdempotencyKeyring | None,
    *,
    exact_nonce_counts: bool,
) -> None:
    try:
        with conn.transaction():
            if keyring is not None:
                for registration in keyring.registrations:
                    conn.execute(
                        """
                        INSERT INTO idempotency_cipher_key_versions (
                            version_label,
                            key_commitment,
                            reserved_encryption_slots,
                            first_seen_epoch
                        )
                        VALUES (
                            %s,
                            %s,
                            0,
                            FLOOR(EXTRACT(EPOCH FROM transaction_timestamp()))::BIGINT
                        )
                        ON CONFLICT (version_label) DO NOTHING
                        """,
                        (registration.version, registration.commitment),
                    )
            registry = tuple(
                IdempotencyKeyRegistration(
                    version=IdempotencyKeyVersionLabel(str(row[0])),
                    commitment=IdempotencyKeyCommitment(bytes(row[1])),
                )
                for row in conn.execute(
                    "SELECT version_label, key_commitment "
                    "FROM idempotency_cipher_key_versions ORDER BY version_label"
                ).fetchall()
            )
            required_versions = tuple(
                str(row[0])
                for row in conn.execute(
                    "SELECT DISTINCT cipher_key_version FROM idempotency_results "
                    "ORDER BY cipher_key_version"
                ).fetchall()
            )
            validate_startup_compatibility(
                keyring=keyring,
                registry=registry,
                unexpired_result_versions=required_versions,
            )
            if not postgres_idempotency_ready(
                conn,
                keyring,
                exact_nonce_counts=exact_nonce_counts,
            ):
                raise IdempotencyKeyringConfigError
    except UniqueViolation:
        raise IdempotencyKeyringConfigError from None


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


class PostgresAgentIssuableScopeBoundsRepository:
    # ADR 0019: issuable scope bounds are control-plane state, so the repository
    # cannot exist without an audit path — the auditor is a required argument
    # and must write through THIS connection (one transaction, one commit).
    def __init__(self, conn: Any, control_auditor: ControlPlaneAuditor) -> None:
        self._conn = conn
        control_auditor.require_bound_to(conn)
        self._control_auditor = control_auditor

    def get_bounds(self, *, workspace_id: str, agent_id: str) -> tuple[str, ...] | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT scopes_json FROM agent_issuable_scope_bounds
                WHERE workspace_id = %s AND agent_id = %s
                """,
                (workspace_id, agent_id),
            ).fetchone()
        if row is None:
            return None
        scopes = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        return tuple(scopes)

    def get_max_ttl_seconds(self, *, workspace_id: str, agent_id: str) -> int | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT max_ttl_seconds FROM agent_issuable_scope_bounds
                WHERE workspace_id = %s AND agent_id = %s
                """,
                (workspace_id, agent_id),
            ).fetchone()
        return row[0] if row is not None else None

    def get_bounds_with_max_ttl(
        self, *, workspace_id: str, agent_id: str
    ) -> AgentIssuableBounds | None:
        # Single-row read: scopes and max TTL come from one consistent snapshot
        # of the bounds row (no torn read across a concurrent set_bounds).
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT scopes_json, max_ttl_seconds FROM agent_issuable_scope_bounds
                WHERE workspace_id = %s AND agent_id = %s
                """,
                (workspace_id, agent_id),
            ).fetchone()
        if row is None:
            return None
        scopes = json.loads(row[0]) if isinstance(row[0], str) else row[0]
        return AgentIssuableBounds(scopes=tuple(scopes), max_ttl_seconds=row[1])

    def list_bounds_for_workspace(self, workspace_id: str) -> ScopeBoundsListing:
        with self._conn.transaction():
            rows = self._conn.execute(
                """
                SELECT agent_id, scopes_json FROM agent_issuable_scope_bounds
                WHERE workspace_id = %s
                ORDER BY agent_id
                """,
                (workspace_id,),
            ).fetchall()
        return tuple(
            (
                row[0],
                tuple(json.loads(row[1]) if isinstance(row[1], str) else row[1]),
            )
            for row in rows
        )

    def set_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        clear_max_ttl: bool = False,
        now: datetime,
        enforcing_principal: str | None = None,
    ) -> None:
        validate_issuable_scope_bounds(scopes, max_ttl_seconds=max_ttl_seconds)
        validate_clear_max_ttl(max_ttl_seconds=max_ttl_seconds, clear_max_ttl=clear_max_ttl)
        # The bounds change and its control audit event commit as ONE unit (the
        # audit writer's nested transaction() becomes a savepoint under this).
        with self._conn.transaction():
            # Partial update: an undeclared max TTL (NULL, not clearing)
            # COALESCEs to the stored cap so re-declaring the scopes never
            # silently widens issuable authority (PKA-102). Removing the cap
            # is the explicit clear_max_ttl act.
            self._conn.execute(
                """
                INSERT INTO agent_issuable_scope_bounds (
                    workspace_id, agent_id, scopes_json, max_ttl_seconds, updated_at
                ) VALUES (%s, %s, %s::jsonb, %s, %s)
                ON CONFLICT (workspace_id, agent_id) DO UPDATE SET
                    scopes_json = EXCLUDED.scopes_json,
                    max_ttl_seconds = CASE
                        WHEN %s THEN NULL
                        ELSE COALESCE(
                            EXCLUDED.max_ttl_seconds,
                            agent_issuable_scope_bounds.max_ttl_seconds
                        )
                    END,
                    updated_at = EXCLUDED.updated_at
                """,
                (
                    workspace_id,
                    agent_id,
                    json.dumps(list(scopes)),
                    max_ttl_seconds,
                    now,
                    clear_max_ttl,
                ),
            )
            self._control_auditor.record(
                event_type=EVENT_SCOPE_BOUNDS_SET,
                workspace_id=workspace_id,
                agent_id=agent_id,
                action="set_issuable_scope_bounds",
                resource=f"issuable_scope_bounds/{agent_id}",
                reason=set_bounds_audit_reason(
                    max_ttl_seconds=max_ttl_seconds, clear_max_ttl=clear_max_ttl
                ),
                scope_attempted=" ".join(scopes),
                now=now,
                enforcing_principal=enforcing_principal,
            )


class PostgresAutoApprovalRuleRepository:
    def __init__(self, conn: Any, control_auditor: ControlPlaneAuditor) -> None:
        self._conn = conn
        control_auditor.require_bound_to(conn)
        self._control_auditor = control_auditor

    def add_rule(self, rule: AutoApprovalRule) -> None:
        with self._conn.transaction():
            self._conn.execute(
                """
                INSERT INTO auto_approval_rules (
                    rule_id, workspace_id, name, target_agent_id,
                    allowed_scopes_json, max_ttl_seconds, status,
                    created_by, created_at, updated_by, updated_at
                ) VALUES (%s, %s, %s, %s, %s::jsonb, %s, %s, %s, %s, %s, %s)
                """,
                _postgres_auto_approval_values(rule),
            )
            self._control_auditor.record(
                event_type=EVENT_AUTO_APPROVAL_RULE_CREATED,
                workspace_id=rule.workspace_id,
                action="create_auto_approval_rule",
                resource=f"auto_approval_rule/{rule.rule_id}",
                reason=f"status={rule.status}",
                now=rule.created_at,
                enforcing_principal=rule.created_by or None,
            )

    def get_rule(self, rule_id: str) -> AutoApprovalRule | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT rule_id, workspace_id, name, target_agent_id,
                       allowed_scopes_json, max_ttl_seconds, status,
                       created_by, created_at, updated_by, updated_at
                FROM auto_approval_rules
                WHERE rule_id = %s
                """,
                (rule_id,),
            ).fetchone()
        return _postgres_auto_approval_from_row(row)

    def list_rules_for_workspace(self, workspace_id: str) -> tuple[AutoApprovalRule, ...]:
        with self._conn.transaction():
            rows = self._conn.execute(
                """
                SELECT rule_id, workspace_id, name, target_agent_id,
                       allowed_scopes_json, max_ttl_seconds, status,
                       created_by, created_at, updated_by, updated_at
                FROM auto_approval_rules
                WHERE workspace_id = %s
                ORDER BY created_at, rule_id
                """,
                (workspace_id,),
            ).fetchall()
        return tuple(
            rule
            for row in rows
            if (rule := _postgres_auto_approval_from_row(row)) is not None
        )

    def update_rule(self, rule: AutoApprovalRule) -> None:
        with self._conn.transaction():
            # Read the prior state INSIDE the transaction and lock the row FOR
            # UPDATE so a concurrent updater on another connection serializes
            # behind this one instead of racing between the read and the UPDATE
            # (which could otherwise record a false before/after transition).
            # This mirrors SQLite's BEGIN IMMEDIATE serialization of the path.
            prior_row = self._conn.execute(
                """
                SELECT rule_id, workspace_id, name, target_agent_id,
                       allowed_scopes_json, max_ttl_seconds, status,
                       created_by, created_at, updated_by, updated_at
                FROM auto_approval_rules
                WHERE rule_id = %s
                FOR UPDATE
                """,
                (rule.rule_id,),
            ).fetchone()
            prior = _postgres_auto_approval_from_row(prior_row)
            if prior is None:
                raise ValueError(f"unknown auto-approval rule_id: {rule.rule_id}")
            self._conn.execute(
                """
                UPDATE auto_approval_rules
                SET workspace_id = %s, name = %s, target_agent_id = %s,
                    allowed_scopes_json = %s::jsonb, max_ttl_seconds = %s,
                    status = %s, created_by = %s, created_at = %s,
                    updated_by = %s, updated_at = %s
                WHERE rule_id = %s
                """,
                (*_postgres_auto_approval_values(rule)[1:], rule.rule_id),
            )
            # EVERY direct update is audited, not just disable (PKA-56 B1).
            control = auto_approval_update_control_event(prior, rule)
            self._control_auditor.record(
                event_type=control.event_type,
                workspace_id=rule.workspace_id,
                action=control.action,
                resource=f"auto_approval_rule/{rule.rule_id}",
                reason=control.reason,
                scope_attempted=control.scope_attempted,
                now=rule.updated_at or rule.created_at,
                enforcing_principal=rule.updated_by or None,
            )


def _boundary_control_operation(operation: str) -> tuple[str, str]:
    if operation == "register":
        return EVENT_BOUNDARY_REGISTERED, "register_boundary"
    if operation == "enable":
        return EVENT_BOUNDARY_STATUS_CHANGED, "enable_boundary"
    if operation == "disable":
        return EVENT_BOUNDARY_STATUS_CHANGED, "disable_boundary"
    raise ValueError(f"unknown boundary operation: {operation}")


class PostgresBoundaryRegistry:
    def __init__(self, conn: Any, control_auditor: ControlPlaneAuditor) -> None:
        self._conn = conn
        control_auditor.require_bound_to(conn)
        self._control_auditor = control_auditor

    def add(self, boundary: Boundary) -> Boundary:
        # The bare BoundaryRegistry.add() contract carries no principal, so a
        # durable registry cannot honor it without emitting a NULL-principal
        # control event — the exact PKA-56 B4 regression this design prevents.
        # The core helpers always reach durable registries through the
        # add_audited probe; a direct bare add() is misuse and must fail loudly.
        raise NotImplementedError(
            "PostgresBoundaryRegistry is audited: use add_audited(boundary, "
            "operation=..., enforcing_principal=...); bare add() would drop "
            "PKA-56 B4 attribution"
        )

    def add_audited(
        self,
        boundary: Boundary,
        *,
        operation: str,
        enforcing_principal: str,
    ) -> Boundary:
        # Durable, audited channel. The core helpers route here (they probe for
        # add_audited) so the overridable BoundaryRegistry.add() contract stays
        # (self, boundary): both the operation (selects the control event) and
        # the enforcing_principal (attributes it, PKA-56 B4) arrive as explicit
        # params. enforcing_principal is REQUIRED and a missing/empty value is
        # rejected before any write, so a durable control event is never left
        # unattributed. Row write and control event share one transaction so
        # the event is atomic with the mutation.
        if not enforcing_principal:
            raise ValueError("enforcing_principal is required for an audited boundary mutation")
        event_type, action = _boundary_control_operation(operation)
        try:
            with self._conn.transaction():
                self._conn.execute(
                    """
                    INSERT INTO boundaries (
                        boundary_id, workspace_id, name, runtime, boundary_type,
                        mode, status, created_at, updated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (boundary_id) DO UPDATE SET
                        workspace_id = EXCLUDED.workspace_id,
                        name = EXCLUDED.name,
                        runtime = EXCLUDED.runtime,
                        boundary_type = EXCLUDED.boundary_type,
                        mode = EXCLUDED.mode,
                        status = EXCLUDED.status,
                        created_at = EXCLUDED.created_at,
                        updated_at = EXCLUDED.updated_at
                    """,
                    (
                        boundary.boundary_id,
                        boundary.workspace_id,
                        boundary.name,
                        boundary.runtime,
                        boundary.boundary_type,
                        boundary.mode,
                        boundary.status,
                        boundary.created_at,
                        boundary.updated_at,
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
                    enforcing_principal=enforcing_principal,
                )
        except Exception as exc:
            if getattr(exc, "sqlstate", None) == "23505":
                raise ValueError("boundary name must be unique within workspace") from exc
            raise
        return boundary

    def get(self, boundary_id: str) -> Boundary | None:
        with self._conn.transaction():
            row = self._conn.execute(
                """
                SELECT boundary_id, workspace_id, name, runtime, boundary_type,
                       mode, status, created_at, updated_at
                FROM boundaries
                WHERE boundary_id = %s
                """,
                (boundary_id,),
            ).fetchone()
        return _boundary_from_row(row)

    def list_for_workspace(self, workspace_id: str) -> list[Boundary]:
        with self._conn.transaction():
            rows = self._conn.execute(
                """
                SELECT boundary_id, workspace_id, name, runtime, boundary_type,
                       mode, status, created_at, updated_at
                FROM boundaries
                WHERE workspace_id = %s
                ORDER BY created_at, boundary_id
                """,
                (workspace_id,),
            ).fetchall()
        return [boundary for row in rows if (boundary := _boundary_from_row(row))]


class PostgresAgentEnforcementSettingsRepository:
    # Maps each enforcement setting column to the presence bit that records
    # whether the setting was explicitly written for the row. Rows are shared
    # between the three settings, so "a row exists" must never be read as "the
    # agent explicitly set this mandate".
    _PRESENCE = {
        "require_boundary": "require_boundary_set",
        "require_subject_token": "require_subject_token_set",
        "require_pop": "require_pop_set",
    }
    _COLUMNS = frozenset(_PRESENCE)

    # ADR 0019: the enforcement mandates are control-plane state, so the
    # repository cannot exist without an audit path — the auditor is required
    # and must write through THIS connection (one transaction, one commit).
    def __init__(self, conn: Any, control_auditor: ControlPlaneAuditor) -> None:
        self._conn = conn
        control_auditor.require_bound_to(conn)
        self._control_auditor = control_auditor
        with self._conn.transaction():
            default_row = self._conn.execute(
                """
                SELECT column_default
                FROM information_schema.columns
                WHERE table_schema = current_schema()
                  AND table_name = 'agent_enforcement_settings'
                  AND column_name = 'require_boundary'
                """
            ).fetchone()
        if default_row is None:
            raise RuntimeError("require_boundary schema default is unavailable")
        self._require_boundary_default = str(default_row[0]).strip().lower() == "true"

    def _get(self, column: str, *, workspace_id: str, agent_id: str) -> bool | None:
        if column not in self._COLUMNS:
            raise ValueError("unknown enforcement setting")
        presence = self._PRESENCE[column]
        with self._conn.transaction():
            row = self._conn.execute(
                f"""
                SELECT {column} FROM agent_enforcement_settings
                WHERE workspace_id = %s AND agent_id = %s AND {presence}
                """,
                (workspace_id, agent_id),
            ).fetchone()
        return bool(row[0]) if row is not None else None

    def _required(self, column: str, *, workspace_id: str, agent_id: str) -> bool:
        agent = self._get(column, workspace_id=workspace_id, agent_id=agent_id)
        if agent is not None:
            return agent
        workspace = self._get(column, workspace_id=workspace_id, agent_id="")
        if workspace is not None:
            return workspace
        return self._require_boundary_default if column == "require_boundary" else False

    def _set(
        self,
        column: str,
        *,
        workspace_id: str,
        agent_id: str,
        value: bool,
        now: datetime,
        enforcing_principal: str | None = None,
    ) -> None:
        if column not in self._COLUMNS:
            raise ValueError("unknown enforcement setting")
        presence = self._PRESENCE[column]
        # On INSERT every presence bit is written explicitly (its own = TRUE,
        # the other two = FALSE): an ALTER-time column default is baked into
        # each migrated database, so relying on defaults for the un-set bits
        # is unsafe. On conflict only this setting's value and presence bit
        # are touched, preserving the other two.
        other_bits = ", ".join(
            bit for name, bit in self._PRESENCE.items() if name != column
        )
        # The mandate change and its control audit event commit as ONE unit
        # (the audit writer's nested transaction() becomes a savepoint).
        with self._conn.transaction():
            self._conn.execute(
                f"""
                INSERT INTO agent_enforcement_settings (
                    workspace_id, agent_id, {column},
                    {presence}, {other_bits}, updated_at
                ) VALUES (%s, %s, %s, TRUE, FALSE, FALSE, %s)
                ON CONFLICT (workspace_id, agent_id) DO UPDATE SET
                    {column} = EXCLUDED.{column},
                    {presence} = TRUE,
                    updated_at = EXCLUDED.updated_at
                """,
                (workspace_id, agent_id, value, now),
            )
            self._control_auditor.record(
                event_type=EVENT_ENFORCEMENT_SETTING_CHANGED,
                workspace_id=workspace_id,
                agent_id=agent_id,
                action=f"set_{column}",
                resource=f"enforcement_setting/{column}",
                reason=f"{column}={'true' if value else 'false'}",
                now=now,
                enforcing_principal=enforcing_principal,
            )

    def get_require_boundary(self, *, workspace_id: str, agent_id: str) -> bool:
        setting = self._get(
            "require_boundary", workspace_id=workspace_id, agent_id=agent_id
        )
        return setting if setting is not None else self._require_boundary_default

    def get_require_boundary_setting(
        self, *, workspace_id: str, agent_id: str
    ) -> bool | None:
        return self._get("require_boundary", workspace_id=workspace_id, agent_id=agent_id)

    def is_boundary_required(self, *, workspace_id: str, agent_id: str) -> bool:
        return self._required("require_boundary", workspace_id=workspace_id, agent_id=agent_id)

    def list_require_boundary(self, workspace_id: str) -> tuple[tuple[str, bool], ...]:
        with self._conn.transaction():
            rows = self._conn.execute(
                """
                SELECT agent_id, require_boundary
                FROM agent_enforcement_settings
                WHERE workspace_id = %s AND require_boundary_set
                ORDER BY agent_id
                """,
                (workspace_id,),
            ).fetchall()
        return tuple((row[0], bool(row[1])) for row in rows)

    def set_require_boundary(
        self, *, workspace_id: str, agent_id: str, require_boundary: bool, now: datetime,
        enforcing_principal: str | None = None,
    ) -> None:
        self._set(
            "require_boundary",
            workspace_id=workspace_id,
            agent_id=agent_id,
            value=require_boundary,
            now=now,
            enforcing_principal=enforcing_principal,
        )

    def get_require_subject_token_setting(
        self, *, workspace_id: str, agent_id: str
    ) -> bool | None:
        return self._get(
            "require_subject_token", workspace_id=workspace_id, agent_id=agent_id
        )

    def is_subject_token_required(self, *, workspace_id: str, agent_id: str) -> bool:
        return self._required(
            "require_subject_token", workspace_id=workspace_id, agent_id=agent_id
        )

    def set_require_subject_token(
        self, *, workspace_id: str, agent_id: str, require_subject_token: bool, now: datetime,
        enforcing_principal: str | None = None,
    ) -> None:
        self._set(
            "require_subject_token",
            workspace_id=workspace_id,
            agent_id=agent_id,
            value=require_subject_token,
            now=now,
            enforcing_principal=enforcing_principal,
        )

    def get_require_pop_setting(
        self, *, workspace_id: str, agent_id: str
    ) -> bool | None:
        return self._get("require_pop", workspace_id=workspace_id, agent_id=agent_id)

    def is_pop_required(self, *, workspace_id: str, agent_id: str) -> bool:
        return self._required("require_pop", workspace_id=workspace_id, agent_id=agent_id)

    def set_require_pop(
        self, *, workspace_id: str, agent_id: str, require_pop: bool, now: datetime,
        enforcing_principal: str | None = None,
    ) -> None:
        self._set(
            "require_pop",
            workspace_id=workspace_id,
            agent_id=agent_id,
            value=require_pop,
            now=now,
            enforcing_principal=enforcing_principal,
        )

class PostgresAuditWriter:
    def __init__(self, conn: Any, anchor: AuditAnchor | None = None) -> None:
        self._conn = conn
        self._anchor = anchor if anchor is not None else NullAnchor()

    def write(self, event: AuditEvent) -> None:
        with self._conn.transaction():
            seq, current_hash, created = self._write_event(event)
        self.emit_or_defer(lambda: self._anchor.emit(seq, current_hash, created))

    def write_best_effort(self, event: AuditEvent) -> bool:
        try:
            with self._conn.transaction():
                seq, current_hash, created = self._write_event(event)
        except Exception:
            return False
        self.emit_or_defer(lambda: self._anchor.emit(seq, current_hash, created))
        return True

    def _write_event(self, event: AuditEvent) -> tuple[int, str, str]:
        event_json = json.dumps(event.to_dict(), sort_keys=True)
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
                first_seen_at, last_seen_at, subject_token_verified, token_id,
                event_class, event_json, seq, prev_hash, row_hash
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
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
                event.subject_token_verified,
                event.token_id,
                event.event_class,
                event_json,
                seq,
                previous_hash,
                current_hash,
            ),
        )
        created = event.created_at.isoformat()
        return seq, current_hash, created

    def emit_or_defer(self, emission: Callable[[], None]) -> None:
        """Run a post-commit audit side effect now, or defer it to this
        connection's outermost transaction commit if one is open (dropped on
        rollback). Fail-open. Mirrors SQLiteAuditWriter.emit_or_defer."""
        self._conn.emit_or_defer(emission)

    # Materialized columns cross-checked against event_json during verification.
    # MUST stay identical to SQLiteAuditWriter._CROSSCHECK_COLUMNS — a parity test
    # (tests/test_audit_hash_chain_sqlite.py) guards against drift so both backends
    # detect the same tampering.
    _CROSSCHECK_COLUMNS = (
        "event_id", "event_type", "decision", "reason", "workspace_id", "agent_id",
        "grant_id", "grant_ref", "action", "resource", "scope_attempted",
        "scope_matched", "boundary_id", "runtime", "boundary_type", "created_at",
        "subject_token_verified", "event_class",
    )

    # Postgres additionally materializes these event_json fields as dedicated
    # columns that list_filtered reads directly (SQLite keeps them JSON-only and
    # filters via json_extract, so it has no such columns to tamper with). Every
    # one of them is cross-checked too: an attacker who edits e.g. reason_code or
    # one of these without touching the hashed event_json must not pass
    # verification. Guarded by tests/test_audit_hash_chain_sqlite.py.
    _PG_ONLY_CROSSCHECK_COLUMNS = (
        "enforcing_principal", "reason_code", "occurrence_count",
        "first_seen_at", "last_seen_at", "token_id",
    )

    def verify_chain(self) -> ChainVerification:
        # Byte-for-byte parity with SQLiteAuditWriter.verify_chain: walk seq order,
        # checking continuity, prev_hash linkage, row_hash recompute (event_json is
        # stored TEXT, so it hashes identically), and event_json vs materialized
        # columns. A write-access forger who recomputes the chain still passes
        # (plain SHA-256) — that gap is tracked separately (audit HMAC design).
        crosscheck_columns = self._CROSSCHECK_COLUMNS + self._PG_ONLY_CROSSCHECK_COLUMNS
        with self._conn.transaction():
            rows = self._conn.execute(
                "SELECT seq, prev_hash, row_hash, event_json, "
                + ", ".join(crosscheck_columns)
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
            for name, value in zip(crosscheck_columns, cols, strict=False):
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
        with self._conn.transaction():
            row = self._conn.execute(
                "SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return (row[0], row[1]) if row else (0, GENESIS_PREV_HASH)

    def verify_against_anchor(self, records: list[AnchorRecord]) -> AnchorVerification:
        covered = 0
        for rec in records:
            with self._conn.transaction():
                row = self._conn.execute(
                    "SELECT row_hash FROM audit_events WHERE seq = %s", (rec.seq,)
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

    def list_auth_failures(self, *, limit: int) -> tuple[AuditEvent, ...]:
        # Pre-auth auth failures are recorded under the empty workspace; order
        # by the monotonic chain seq (Postgres has no rowid) and return oldest
        # first, mirroring the SQLite reader.
        with self._conn.transaction():
            rows = self._conn.execute(
                """
                SELECT event_json FROM audit_events
                WHERE workspace_id = '' AND event_type = 'auth_failed'
                ORDER BY seq DESC
                LIMIT %s
                """,
                (limit,),
            ).fetchall()
        return tuple(_audit_event_from_json(row[0]) for row in reversed(rows))

    def event_sequences(
        self,
        workspace_id: str,
        event_ids: tuple[str, ...],
    ) -> dict[str, int]:
        if not event_ids:
            return {}
        placeholders = ", ".join("%s" for _ in event_ids)
        with self._conn.transaction():
            rows = self._conn.execute(
                "SELECT event_id, seq FROM audit_events "
                "WHERE workspace_id = %s "
                f"AND event_id IN ({placeholders})",
                (workspace_id, *event_ids),
            ).fetchall()
        return {row[0]: row[1] for row in rows}

    def list_filtered(
        self,
        workspace_id: str,
        *,
        event_class: str | None = None,
        event_type: str | None = None,
        grant_ref: str | None = None,
        boundary_id: str | None = None,
        agent_id: str | None = None,
        request_id: str | None = None,
        reason_code: str | None = None,
        enforcing_principal: str | None = None,
        subject_token_verified: bool | None = None,
        snapshot_event_id: str | None = None,
        before_event_id: str | None = None,
        limit: int | None = None,
    ) -> tuple[AuditEvent, ...]:
        validate_audit_event_class(event_class)
        if before_event_id is not None and snapshot_event_id is None:
            raise InvalidAuditCursorError
        snapshot_seq = None
        before_seq = None
        with self._conn.transaction():
            if snapshot_event_id is not None:
                row = self._conn.execute(
                    "SELECT seq FROM audit_events "
                    "WHERE event_id = %s AND workspace_id = %s",
                    (snapshot_event_id, workspace_id),
                ).fetchone()
                if row is None:
                    raise InvalidAuditCursorError
                snapshot_seq = row[0]
            if before_event_id is not None:
                row = self._conn.execute(
                    "SELECT seq FROM audit_events "
                    "WHERE event_id = %s AND workspace_id = %s",
                    (before_event_id, workspace_id),
                ).fetchone()
                if row is None:
                    raise InvalidAuditCursorError
                before_seq = row[0]
        if (
            snapshot_seq is not None
            and before_seq is not None
            and before_seq > snapshot_seq
        ):
            raise InvalidAuditCursorError
        clauses = ["workspace_id = %s"]
        params: list[object] = [workspace_id]
        if snapshot_seq is not None:
            clauses.append("seq <= %s")
            params.append(snapshot_seq)
        if before_seq is not None:
            clauses.append("seq < %s")
            params.append(before_seq)
        filters = (
            ("event_class", event_class),
            ("event_type", event_type),
            ("grant_ref", grant_ref),
            ("boundary_id", boundary_id),
            ("agent_id", agent_id),
            ("reason_code", reason_code),
            ("enforcing_principal", enforcing_principal),
            ("subject_token_verified", subject_token_verified),
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
    storage_backend = "postgres"

    def __init__(
        self,
        conn: Any,
        *,
        initialize_schema: bool = True,
        idempotency_keyring: IdempotencyKeyring | None = None,
    ) -> None:
        self.conn = conn
        self.idempotency_keyring = idempotency_keyring
        self._writer_attestation: PostgresWriterAttestation | None = None
        if initialize_schema:
            init_postgres_schema(conn)
        else:
            # Mirror SQLiteV1Service: skipping the schema APPLY must not skip
            # the version gate — a database newer than this binary is refused
            # on every construction path (PKA-40), not only the initializing one.
            # Run the gate inside a transaction so the connection is left IDLE
            # whether the gate passes (commit) or refuses (rollback), matching
            # init_postgres_schema. A bare execute would open an implicit
            # transaction that stays open past a raise, leaving the connection
            # mid-transaction for the caller.
            with conn.transaction():
                _assert_postgres_schema_supported(conn)
        with ExitStack() as registration:
            if self.idempotency_keyring is not None:
                writer_attestation = PostgresWriterAttestation(
                    conn,
                    self.idempotency_keyring.active_version,
                )
                registration.callback(writer_attestation.close)
                with writer_attestation.registration_guard():
                    _register_postgres_idempotency_keyring(
                        conn,
                        self.idempotency_keyring,
                        exact_nonce_counts=initialize_schema,
                    )
                self._writer_attestation = writer_attestation
            else:
                _register_postgres_idempotency_keyring(
                    conn,
                    self.idempotency_keyring,
                    exact_nonce_counts=initialize_schema,
                )
            registration.pop_all()
        self.idempotency_executor = PostgresIdempotentMutationExecutor(
            PostgresIdempotencyStore(
                conn,
                keyring=self.idempotency_keyring,
            )
        )
        self.grant_repository = PostgresGrantRepository(conn)
        sinks = audit_sinks_from_env(dict(os.environ))
        self.audit_writer = PostgresAuditWriter(conn, anchor=sinks.anchor)
        # Opt-in SIEM/OTel export (VINCTOR_AUDIT_EXPORT): mirror SQLite — when set,
        # wrap the durable writer so each persisted event is ALSO streamed,
        # fail-open, after the write. Off (NullExport) leaves the writer as-is.
        export = sinks.export
        if not isinstance(export, NullExport):
            self.audit_writer = ExportingAuditWriter(self.audit_writer, export)
        # Control-plane mutations audit through the SAME (possibly
        # export-wrapped) writer as decisions: one chain, one clock (ADR 0019).
        self.control_auditor = ControlPlaneAuditor(self.audit_writer)
        self.boundary_registry = PostgresBoundaryRegistry(
            conn, self.control_auditor
        )
        self.scope_bounds_repository = PostgresAgentIssuableScopeBoundsRepository(
            conn, self.control_auditor
        )
        self.grant_request_repository = PostgresGrantRequestRepository(conn)
        self.auto_approval_rule_repository = PostgresAutoApprovalRuleRepository(
            conn, self.control_auditor
        )
        self.subject_token_repository = PostgresSubjectTokenRepository(conn)
        self.agent_enforcement_settings_repository = (
            PostgresAgentEnforcementSettingsRepository(conn, self.control_auditor)
        )
        self._pop_replay = PostgresReplayStore(conn)
        self._auth_failures = AuthFailureAuditThrottle()

    @property
    def audit_events(self) -> tuple[AuditEvent, ...]:
        return tuple(self.audit_writer.list_all())

    def get_audit_event(self, event_id: str) -> AuditEvent | None:
        return self.audit_writer.get(event_id)

    def list_filtered(self, workspace_id: str, **filters: Any) -> tuple[AuditEvent, ...]:
        return self.audit_writer.list_filtered(workspace_id, **filters)

    def audit_event_sequences(
        self,
        workspace_id: str,
        event_ids: tuple[str, ...],
    ) -> dict[str, int]:
        return self.audit_writer.event_sequences(workspace_id, event_ids)

    def list_auth_failures(self, *, limit: int) -> tuple[AuditEvent, ...]:
        return self.audit_writer.list_auth_failures(limit=limit)

    def execute_idempotent(
        self,
        invocation: IdempotencyInvocation,
        mutation: IdempotencyMutation,
    ) -> PreSerializedHttpResponse:
        return self.idempotency_executor.execute(invocation, mutation)

    def close(self) -> None:
        writer_attestation = self._writer_attestation
        if writer_attestation is None:
            return
        writer_attestation.close()
        self._writer_attestation = None

    def insert_grant(self, grant: Grant) -> None:
        self.grant_repository.insert(grant)

    def issue_grant(
        self, request: GrantIssueRequest, *, now: datetime,
    ) -> GrantIssueResult:
        # State change and its audit row commit together (or not at all).
        with self.conn.transaction():
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
        self, *, workspace_id: str, agent_id: str | None = None,
        status: str | None = None,
    ) -> tuple[Grant, ...]:
        return list_grants(
            workspace_id=workspace_id,
            agent_id=agent_id,
            status=status,
            grant_repository=self.grant_repository,
        )

    def revoke_grant(
        self, *, grant_ref: str, workspace_id: str, now: datetime,
    ) -> tuple[Grant, str] | None:
        with self.conn.transaction():
            return revoke_grant(
                grant_ref=grant_ref,
                workspace_id=workspace_id,
                grant_repository=self.grant_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def set_agent_issuable_scope_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        clear_max_ttl: bool = False,
        now: datetime,
        enforcing_principal: str | None = None,
    ) -> None:
        self.scope_bounds_repository.set_bounds(
            workspace_id=workspace_id,
            agent_id=agent_id,
            scopes=scopes,
            max_ttl_seconds=max_ttl_seconds,
            clear_max_ttl=clear_max_ttl,
            now=now,
            enforcing_principal=enforcing_principal,
        )

    def create_grant_request(
        self, request: GrantRequestCreateRequest, *, now: datetime,
    ) -> GrantRequestCreateResult:
        with self.conn.transaction():
            return create_grant_request(
                request,
                request_repository=self.grant_request_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def lookup_grant_request(
        self, *, request_id: str, workspace_id: str,
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
        self, *, request_id: str, workspace_id: str, decided_by: str,
        decision_reason: str | None, now: datetime,
    ) -> GrantRequestDecisionResult:
        with _grant_request_decision_transaction(self.conn, request_id):
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
        self, *, request_id: str, workspace_id: str, decided_by: str,
        decision_reason: str | None, now: datetime,
    ) -> GrantRequestDecisionResult:
        with _grant_request_decision_transaction(self.conn, request_id):
            return reject_grant_request(
                request_id=request_id,
                workspace_id=workspace_id,
                decided_by=decided_by,
                decision_reason=decision_reason,
                request_repository=self.grant_request_repository,
                audit_writer=self.audit_writer,
                now=now,
            )

    def mint_subject_token(
        self, *, workspace_id, agent_id, grant_ref, audience, ttl_seconds, now,
        bound_action=None, bound_resource=None, pop=False,
    ):
        # Only the SUCCESSFUL mint's state+audit pair is wrapped in a transaction
        # (injected via ``atomic``); the FORBIDDEN path writes its best-effort
        # rejection audit standalone, exactly like the enforce/simulate rejection
        # audits — so a forbidden probe opens no fallible outer commit and its
        # audit failure never changes the generic forbidden result. Mirrors the
        # SQLite service wrapper.
        return mint_subject_token(
            grant_repository=self.grant_repository,
            subject_token_repository=self.subject_token_repository,
            audit_writer=self.audit_writer,
            workspace_id=workspace_id,
            agent_id=agent_id,
            grant_ref=grant_ref,
            audience=audience,
            ttl_seconds=ttl_seconds,
            now=now,
            bound_action=bound_action,
            bound_resource=bound_resource,
            pop=pop,
            atomic=lambda: self.conn.transaction(),
        )

    def create_auto_approval_rule(self, rule: AutoApprovalRule) -> AutoApprovalRule:
        return create_auto_approval_rule(
            rule_repository=self.auto_approval_rule_repository,
            rule=rule,
        )

    def list_auto_approval_rules(
        self, workspace_id: str,
    ) -> tuple[AutoApprovalRule, ...]:
        return list_auto_approval_rules(
            rule_repository=self.auto_approval_rule_repository,
            workspace_id=workspace_id,
        )

    def disable_auto_approval_rule(
        self, *, rule_id: str, workspace_id: str, disabled_by: str, now: datetime,
    ) -> AutoApprovalRule | None:
        return disable_auto_approval_rule(
            rule_repository=self.auto_approval_rule_repository,
            rule_id=rule_id,
            workspace_id=workspace_id,
            disabled_by=disabled_by,
            now=now,
        )

    def evaluate_auto_approval(
        self, *, request: GrantRequest,
    ) -> AutoApprovalEvaluationResult:
        return evaluate_auto_approval(
            request=request,
            rule_repository=self.auto_approval_rule_repository,
        )

    def auto_approve_grant_request(
        self, *, request_id: str, workspace_id: str, decided_by: str,
        now: datetime,
    ) -> GrantRequestDecisionResult:
        with _grant_request_decision_transaction(self.conn, request_id):
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

    def register_boundary(
        self, registration: BoundaryRegistrationInput, *,
        now: datetime | None = None, boundary_id: str | None = None,
        enforcing_principal: str | None = None,
    ) -> Boundary:
        return register_boundary(
            self.boundary_registry,
            registration,
            now=now,
            boundary_id=boundary_id,
            enforcing_principal=enforcing_principal,
        )

    def disable_boundary(
        self, *, boundary_id: str, workspace_id: str,
        now: datetime | None = None,
        enforcing_principal: str | None = None,
    ) -> Boundary | None:
        return disable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
            enforcing_principal=enforcing_principal,
        )

    def enable_boundary(
        self, *, boundary_id: str, workspace_id: str,
        now: datetime | None = None,
        enforcing_principal: str | None = None,
    ) -> Boundary | None:
        return enable_boundary(
            self.boundary_registry,
            boundary_id=boundary_id,
            workspace_id=workspace_id,
            now=now,
            enforcing_principal=enforcing_principal,
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

    def simulate(self, request: V1SimulateRequest, *, now: datetime) -> V1SimulateResponse:
        return simulate_v1_contract(
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

    def delegated_enforce(
        self, request: V1DelegatedEnforceRequest, *, now: datetime,
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


def _postgres_auto_approval_values(rule: AutoApprovalRule) -> tuple[object, ...]:
    return (
        rule.rule_id,
        rule.workspace_id,
        rule.name,
        rule.target_agent_id,
        json.dumps(list(rule.allowed_scopes)),
        rule.max_ttl_seconds,
        rule.status,
        rule.created_by,
        rule.created_at,
        rule.updated_by,
        rule.updated_at,
    )


def _postgres_auto_approval_from_row(row: Any) -> AutoApprovalRule | None:
    if row is None:
        return None
    scopes = json.loads(row[4]) if isinstance(row[4], str) else row[4]
    created_at = row[8]
    updated_at = row[10]
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    if updated_at is not None and updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=UTC)
    return AutoApprovalRule(
        rule_id=row[0],
        workspace_id=row[1],
        name=row[2],
        target_agent_id=row[3],
        allowed_scopes=tuple(scopes),
        max_ttl_seconds=row[5],
        status=row[6],
        created_by=row[7],
        created_at=created_at,
        updated_by=row[9],
        updated_at=updated_at,
    )


def _boundary_from_row(row: Any) -> Boundary | None:
    if row is None:
        return None
    created_at = row[7]
    updated_at = row[8]
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=UTC)
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=UTC)
    return Boundary(
        boundary_id=row[0],
        workspace_id=row[1],
        name=row[2],
        runtime=row[3],
        boundary_type=row[4],
        mode=row[5],
        status=row[6],
        created_at=created_at,
        updated_at=updated_at,
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
