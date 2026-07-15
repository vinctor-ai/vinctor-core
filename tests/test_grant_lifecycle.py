from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vinctor_core.audit import (
    EVENT_GRANT_ISSUE_REJECTED,
    REASON_ISSUABLE_BOUNDS_NOT_FOUND,
    REASON_SCOPE_OUTSIDE_ISSUABLE_BOUNDS,
    REASON_TTL_EXCEEDS_ISSUABLE_MAX,
)
from vinctor_service import GrantIssueRequest, SQLiteV1Service, V1EnforceRequest
from vinctor_service.audit import InMemoryAuditWriter
from vinctor_service.grants import DEFAULT_TTL_SECONDS, issue_grant
from vinctor_service.models import AgentIssuableBounds
from vinctor_service.repositories import InMemoryGrantRepository
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def connect_db(tmp_path: Path) -> sqlite3.Connection:
    return connect_sqlite(tmp_path / "vinctor.sqlite")


def issue_request(
    *,
    scopes: tuple[str, ...] = ("execute:ci/test",),
    ttl_seconds: int = 3600,
    grant_ref: str = "grt_issued",
) -> GrantIssueRequest:
    return GrantIssueRequest(
        workspace_id="ws_main",
        target_agent_id="agent_runner",
        requested_scopes=scopes,
        ttl_seconds=ttl_seconds,
        grant_id="grnt_issued",
        grant_ref=grant_ref,
    )


def enforce_request(
    *,
    grant_ref: str = "grt_issued",
    action: str = "execute",
    resource: str = "ci/test",
) -> V1EnforceRequest:
    return V1EnforceRequest(
        workspace_id="ws_main",
        agent_id="agent_runner",
        grant_ref=grant_ref,
        action=action,
        resource=resource,
    )


def audit_rows(conn: sqlite3.Connection) -> list[tuple[str, str, str, str]]:
    return conn.execute(
        """
        SELECT event_type, reason, grant_ref, action
        FROM audit_events
        ORDER BY rowid
        """
    ).fetchall()


def audit_event_decisions(conn: sqlite3.Connection) -> list[tuple[str, str]]:
    return conn.execute(
        """
        SELECT event_type, decision
        FROM audit_events
        ORDER BY rowid
        """
    ).fetchall()


def test_workspace_can_issue_lookup_and_enforce_service_issued_grant(
    tmp_path: Path,
) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test", "execute:ci/build", "read:secret/env"),
        now=NOW,
    )

    issued = service.issue_grant(issue_request(), now=NOW)

    assert issued.status == "issued"
    assert issued.grant is not None
    assert issued.grant.grant_ref == "grt_issued"
    assert issued.grant.expires_at == NOW + timedelta(seconds=3600)
    assert service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main") == issued.grant

    enforced = service.enforce(enforce_request(), now=NOW)

    assert enforced.status_code == 200
    assert enforced.decision == "permit"
    assert audit_rows(conn)[0] == (
        "grant_issued",
        "grant_issued",
        "grt_issued",
        "issue_grant",
    )
    conn.close()


def test_scopes_outside_agent_issuable_bounds_are_rejected(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    result = service.issue_grant(
        issue_request(scopes=("execute:deploy/production",)),
        now=NOW,
    )

    assert result.status == "rejected"
    assert result.reason == "scope_outside_issuable_bounds"
    # Caller-facing detail names the offending scope and the configured bounds so the
    # workspace-key holder can self-correct; the reason stays a low-cardinality code.
    assert result.detail is not None
    assert "execute:deploy/production" in result.detail
    assert "execute:ci/test" in result.detail
    assert service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main") is None
    # ADR 0008: out-of-bounds issuance is recorded for the operator (no grant disclosed).
    assert audit_rows(conn) == [
        (EVENT_GRANT_ISSUE_REJECTED, REASON_SCOPE_OUTSIDE_ISSUABLE_BOUNDS, "", "issue_grant")
    ]
    # The persisted event carries the coarse reason_code (mirrored into reason).
    event_json = json.loads(conn.execute("SELECT event_json FROM audit_events").fetchone()[0])
    assert event_json["reason_code"] == REASON_SCOPE_OUTSIDE_ISSUABLE_BOUNDS
    assert "grt_issued" not in json.dumps(event_json)
    conn.close()


def test_issuance_without_agent_bounds_records_rejection_audit(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    # No issuable bounds are configured for the target agent.

    result = service.issue_grant(issue_request(scopes=("execute:ci/test",)), now=NOW)

    assert result.status == "rejected"
    assert result.reason == "issuable_bounds_not_found"
    assert result.detail is not None
    assert "agent_runner" in result.detail
    # ADR 0008: issuance for an agent with no bounds is recorded for the operator.
    assert audit_rows(conn) == [
        (EVENT_GRANT_ISSUE_REJECTED, REASON_ISSUABLE_BOUNDS_NOT_FOUND, "", "issue_grant")
    ]
    event_json = json.loads(conn.execute("SELECT event_json FROM audit_events").fetchone()[0])
    assert event_json["reason_code"] == REASON_ISSUABLE_BOUNDS_NOT_FOUND
    conn.close()


def test_ttl_expiration_is_enforced_for_issued_grants(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.issue_grant(issue_request(ttl_seconds=1), now=NOW)

    response = service.enforce(enforce_request(), now=NOW + timedelta(seconds=2))

    assert response.status_code == 403
    assert response.error == "grant_expired"
    conn.close()


def test_revoke_marks_grant_revoked_and_writes_audit(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )
    service.issue_grant(issue_request(), now=NOW)

    revoked = service.revoke_grant(
        grant_ref="grt_issued",
        workspace_id="ws_main",
        now=NOW + timedelta(seconds=1),
    )

    assert revoked is not None
    grant, audit_event_id = revoked
    assert grant.status == "revoked"
    assert audit_event_id is not None
    denied = service.enforce(enforce_request(), now=NOW + timedelta(seconds=2))
    assert denied.status_code == 403
    assert denied.error == "grant_revoked"
    assert audit_rows(conn)[:2] == [
        ("grant_issued", "grant_issued", "grt_issued", "issue_grant"),
        ("grant_revoked", "grant_revoked", "grt_issued", "revoke_grant"),
    ]
    assert audit_event_decisions(conn)[:2] == [
        ("grant_issued", "permit"),
        ("grant_revoked", "deny"),
    ]
    conn.close()


def test_missing_ttl_defaults_to_short_ttl(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    issued = service.issue_grant(
        GrantIssueRequest(
            workspace_id="ws_main",
            target_agent_id="agent_runner",
            requested_scopes=("execute:ci/test",),
            grant_id="grnt_issued",
            grant_ref="grt_issued",
        ),
        now=NOW,
    )

    assert issued.status == "issued"
    assert issued.grant is not None
    assert issued.grant.expires_at == NOW + timedelta(seconds=DEFAULT_TTL_SECONDS)

    # The grant_issued audit event references the grant whose persisted expiry
    # reflects the applied (defaulted) TTL, not the omitted requested TTL.
    assert audit_rows(conn)[0][0] == "grant_issued"
    persisted = service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main")
    assert persisted is not None
    assert persisted.expires_at == NOW + timedelta(seconds=DEFAULT_TTL_SECONDS)
    conn.close()


def test_ttl_within_agent_max_ttl_is_issued(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=3600,
        now=NOW,
    )

    issued = service.issue_grant(issue_request(ttl_seconds=1800), now=NOW)

    assert issued.status == "issued"
    assert issued.grant is not None
    assert issued.grant.expires_at == NOW + timedelta(seconds=1800)
    conn.close()


def test_ttl_exceeding_agent_max_ttl_is_rejected(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=1800,
        now=NOW,
    )

    result = service.issue_grant(issue_request(ttl_seconds=3600), now=NOW)

    assert result.status == "rejected"
    assert result.reason == "ttl_exceeds_issuable_max"
    assert result.detail is not None
    assert "3600" in result.detail
    assert "1800" in result.detail
    assert service.lookup_grant(grant_ref="grt_issued", workspace_id="ws_main") is None
    # ADR 0008: TTL over the agent's issuable max is recorded for the operator.
    assert audit_rows(conn) == [
        (EVENT_GRANT_ISSUE_REJECTED, REASON_TTL_EXCEEDS_ISSUABLE_MAX, "", "issue_grant")
    ]
    event_json = json.loads(conn.execute("SELECT event_json FROM audit_events").fetchone()[0])
    assert event_json["reason_code"] == REASON_TTL_EXCEEDS_ISSUABLE_MAX
    conn.close()


def test_ttl_at_agent_max_ttl_boundary_is_issued(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=1800,
        now=NOW,
    )

    result = service.issue_grant(issue_request(ttl_seconds=1800), now=NOW)

    assert result.status == "issued"
    conn.close()


def test_max_ttl_persists_and_is_shown_in_bounds(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=1800,
        now=NOW,
    )

    assert (
        service.scope_bounds_repository.get_max_ttl_seconds(
            workspace_id="ws_main",
            agent_id="agent_runner",
        )
        == 1800
    )
    conn.close()


def test_no_max_ttl_bound_allows_ttl_up_to_ceiling(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    issued = service.issue_grant(issue_request(ttl_seconds=7200), now=NOW)

    assert issued.status == "issued"
    assert (
        service.scope_bounds_repository.get_max_ttl_seconds(
            workspace_id="ws_main",
            agent_id="agent_runner",
        )
        is None
    )
    conn.close()


def test_ttl_exceeding_hard_ceiling_is_rejected(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    result = service.issue_grant(issue_request(ttl_seconds=10**9), now=NOW)

    assert result.status == "rejected"
    assert result.reason == "ttl_exceeds_max"
    assert audit_rows(conn) == []
    conn.close()


def test_lifecycle_audit_event_json_excludes_raw_inputs(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        now=NOW,
    )

    service.issue_grant(issue_request(), now=NOW)

    row = conn.execute("SELECT event_json FROM audit_events").fetchone()
    event_json = json.loads(row[0])
    assert event_json["event_type"] == "grant_issued"
    assert event_json.keys().isdisjoint({"raw_tool_input", "raw_command", "prompt"})
    conn.close()


class TornReadScopeBoundsRepository:
    """Simulates a concurrent set_bounds landing between two separate reads.

    The legacy per-field getters expose a torn view: ``get_bounds`` still sees
    the OLD wide scopes while ``get_max_ttl_seconds`` already sees the NEW max
    TTL. ``get_bounds_with_max_ttl`` returns the one consistent (NEW) row
    snapshot.
    """

    OLD_SCOPES = ("execute:ci/test", "execute:ci/build")
    NEW_SCOPES = ("execute:ci/build",)
    NEW_MAX_TTL_SECONDS = 600

    def __init__(self) -> None:
        self.calls: list[str] = []

    def get_bounds(self, *, workspace_id: str, agent_id: str) -> tuple[str, ...] | None:
        self.calls.append("get_bounds")
        return self.OLD_SCOPES

    def get_max_ttl_seconds(self, *, workspace_id: str, agent_id: str) -> int | None:
        self.calls.append("get_max_ttl_seconds")
        return self.NEW_MAX_TTL_SECONDS

    def get_bounds_with_max_ttl(
        self, *, workspace_id: str, agent_id: str
    ) -> AgentIssuableBounds | None:
        self.calls.append("get_bounds_with_max_ttl")
        return AgentIssuableBounds(
            scopes=self.NEW_SCOPES,
            max_ttl_seconds=self.NEW_MAX_TTL_SECONDS,
        )

    def list_bounds_for_workspace(
        self, workspace_id: str
    ) -> tuple[tuple[str, tuple[str, ...]], ...]:
        return ()

    def set_bounds(
        self,
        *,
        workspace_id: str,
        agent_id: str,
        scopes: tuple[str, ...],
        max_ttl_seconds: int | None = None,
        now: datetime,
    ) -> None:
        raise NotImplementedError


def test_issue_grant_reads_scopes_and_max_ttl_in_one_snapshot() -> None:
    repository = TornReadScopeBoundsRepository()
    # Scope is inside the OLD bounds only; TTL is within the NEW max TTL. The
    # torn (old-scopes, new-max-ttl) mix would issue a grant that neither the
    # fully-old nor the fully-new bounds permit.
    request = issue_request(scopes=("execute:ci/test",), ttl_seconds=600)

    result = issue_grant(
        request,
        grant_repository=InMemoryGrantRepository(),
        scope_bounds_repository=repository,
        audit_writer=InMemoryAuditWriter(),
        now=NOW,
    )

    assert repository.calls == ["get_bounds_with_max_ttl"]
    assert result.status == "rejected"
    assert result.reason == "scope_outside_issuable_bounds"


def test_issue_decisions_against_real_bounds_are_unchanged(tmp_path: Path) -> None:
    conn = connect_db(tmp_path)
    service = SQLiteV1Service(conn)
    service.set_agent_issuable_scope_bounds(
        workspace_id="ws_main",
        agent_id="agent_runner",
        scopes=("execute:ci/test",),
        max_ttl_seconds=1800,
        now=NOW,
    )

    accepted = service.issue_grant(
        issue_request(ttl_seconds=1800, grant_ref="grt_ok"), now=NOW
    )
    assert (accepted.status, accepted.reason) == ("issued", "grant_issued")

    outside = service.issue_grant(
        issue_request(scopes=("read:secret/env",), grant_ref="grt_scope"), now=NOW
    )
    assert (outside.status, outside.reason) == (
        "rejected",
        "scope_outside_issuable_bounds",
    )

    over_ttl = service.issue_grant(
        issue_request(ttl_seconds=3600, grant_ref="grt_ttl"), now=NOW
    )
    assert (over_ttl.status, over_ttl.reason) == ("rejected", "ttl_exceeds_issuable_max")

    unbounded = service.issue_grant(
        GrantIssueRequest(
            workspace_id="ws_main",
            target_agent_id="agent_unbounded",
            requested_scopes=("execute:ci/test",),
            ttl_seconds=600,
            grant_id="grnt_unbounded",
            grant_ref="grt_unbounded",
        ),
        now=NOW,
    )
    assert (unbounded.status, unbounded.reason) == (
        "rejected",
        "issuable_bounds_not_found",
    )
    conn.close()
