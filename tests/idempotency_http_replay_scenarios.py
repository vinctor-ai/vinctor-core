from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from idempotency_http_fixtures import NOW, RawResponse
from idempotency_http_header_scenarios import VALID_GRANT_BODY
from idempotency_http_memory_transport import post_memory_json, post_memory_raw_json
from idempotency_http_terminal_case import RouteCase
from idempotency_sqlite_http_scenarios import (
    PersistedCounts,
    configured_sqlite_service,
    persisted_counts,
    seed_other_workspace,
    seed_success_routes,
)

from vinctor_core import BoundaryRegistrationInput
from vinctor_service import WorkspaceIdentity


@dataclass(frozen=True, slots=True)
class ReplayOutcome:
    first: RawResponse
    replay: RawResponse
    before: PersistedCounts
    after_first: PersistedCounts
    after_replay: PersistedCounts


@dataclass(frozen=True, slots=True)
class ConflictOutcome:
    first: RawResponse
    conflict: RawResponse
    after_first: PersistedCounts
    after_conflict: PersistedCounts


def exercise_scoped_operations(database: Path) -> tuple[int, int, int, int]:
    service, connection = configured_sqlite_service(database)
    seed_success_routes(service)
    seed_other_workspace(service)
    try:
        grant = post_memory_raw_json(
            service,
            "/v1/grants",
            VALID_GRANT_BODY,
            (
                ("X-Workspace-Key", "workspace_key_main"),
                ("Idempotency-Key", "same-scope-key"),
            ),
        )
        token = post_memory_raw_json(
            service,
            "/v1/tokens",
            b'{"grant_ref":"grt_seed","audience":"pep_main","ttl_seconds":60}',
            (
                ("X-Agent-Key", "agent_key_main"),
                ("Idempotency-Key", "same-scope-key"),
            ),
        )
        other_workspace = post_memory_raw_json(
            service,
            "/v1/grants",
            VALID_GRANT_BODY,
            (
                ("X-Workspace-Key", "workspace_key_other"),
                ("Idempotency-Key", "same-scope-key"),
            ),
            workspace_identities={
                "workspace_key_other": WorkspaceIdentity(workspace_id="ws_other")
            },
        )
        return (
            grant.status_code,
            token.status_code,
            other_workspace.status_code,
            persisted_counts(connection).results,
        )
    finally:
        connection.close()


def exercise_conflict(database: Path) -> ConflictOutcome:
    service, connection = configured_sqlite_service(database)
    seed_success_routes(service)
    try:
        first = post_memory_raw_json(
            service,
            "/v1/grants",
            VALID_GRANT_BODY,
            (
                ("X-Workspace-Key", "workspace_key_main"),
                ("Idempotency-Key", "conflict-key"),
            ),
        )
        after_first = persisted_counts(connection)
        conflict = post_memory_raw_json(
            service,
            "/v1/grants",
            b'{"agent_id":"agent_release","scopes":["write:repo/feature/other"],"ttl_seconds":60}',
            (
                ("X-Workspace-Key", "workspace_key_main"),
                ("Idempotency-Key", "conflict-key"),
            ),
        )
        after_conflict = persisted_counts(connection)
        return ConflictOutcome(first, conflict, after_first, after_conflict)
    finally:
        connection.close()


def exercise_replay(database: Path, case: RouteCase) -> ReplayOutcome:
    service, connection = configured_sqlite_service(database)
    seed_success_routes(service)
    if case.label == "boundary-semantic-400":
        service.register_boundary(
            BoundaryRegistrationInput(
                workspace_id="ws_main",
                name="matrix-boundary-invalid",
                runtime="existing-runtime",
                boundary_type="pretooluse",
            ),
            now=NOW,
            boundary_id="bnd_existing",
            enforcing_principal="workspace:ws_main",
        )
    if case.label == "auto-nested-400":
        connection.execute(
            "INSERT INTO agent_issuable_scope_bounds "
            "(workspace_id, agent_id, scopes_json, max_ttl_seconds, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                "ws_main",
                "agent_invalid_bounds",
                '["bad scope"]',
                3_600,
                NOW.isoformat(),
            ),
        )
        connection.commit()
    try:
        before = persisted_counts(connection)
        headers = {**case.headers, "Idempotency-Key": f"matrix-{case.label}"}
        first = post_memory_json(service, case.path, case.payload, headers)
        after_first = persisted_counts(connection)
        replay = post_memory_json(service, case.path, case.payload, headers)
        after_replay = persisted_counts(connection)
        return ReplayOutcome(first, replay, before, after_first, after_replay)
    finally:
        connection.close()


def state_value(counts: PersistedCounts, field: str) -> int:
    return {
        "grants": counts.grants,
        "tokens": counts.tokens,
        "boundaries": counts.boundaries,
        "rules": counts.rules,
        "requests": counts.requests,
    }[field]
