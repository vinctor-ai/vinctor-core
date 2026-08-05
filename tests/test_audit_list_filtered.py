"""Behavior contract for ``list_filtered`` on the audit read service.

T1 (v0.1.1 security hardening): the audit list/export path must push filtering
into SQL (workspace-scoped WHERE/ORDER/LIMIT + index) instead of reading the whole
``audit_events`` table and filtering in Python. ``list_filtered`` must return the
SAME results the current Python-side filter produced: same filters, same ordering
(the most-recent ``limit`` events, oldest-first within that window, matching the old
``[-limit:]`` slice), same 1..100 limit handling, and ALWAYS workspace-scoped.
"""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vinctor_core.models import AuditEvent
from vinctor_service import InMemoryV1Service
from vinctor_service.sqlite import (
    SQLiteV1Service,
    get_sqlite_schema_versions,
    init_sqlite_schema,
)
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def _event(
    *,
    event_id: str,
    event_type: str = "action_denied",
    decision: str = "deny",
    workspace_id: str = "ws_main",
    agent_id: str = "agent_release",
    grant_id: str = "grnt_main",
    grant_ref: str = "grt_main",
    resource: str = "email/external",
    boundary_id: str | None = None,
    created_at: datetime = NOW,
    event_class: str = "decision",
) -> AuditEvent:
    return AuditEvent(
        event_id=event_id,
        event_type=event_type,
        decision=decision,
        reason=event_type,
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_id=grant_id,
        grant_ref=grant_ref,
        action="send",
        resource=resource,
        scope_attempted="send:email/external",
        scope_matched=None,
        boundary_id=boundary_id,
        runtime=None,
        boundary_type=None,
        created_at=created_at,
        event_class=event_class,
    )


def _sqlite_service(tmp_path: Path) -> SQLiteV1Service:
    tmp_path.mkdir(parents=True, exist_ok=True)
    conn = connect_sqlite(tmp_path / "vinctor.sqlite")
    return SQLiteV1Service(conn)


def _both_services(tmp_path: Path) -> list[object]:
    return [InMemoryV1Service(), _sqlite_service(tmp_path)]


# ---------------------------------------------------------------------------
# Schema version: the workspace-sequence index migration bumps the maximum to 17.
# ---------------------------------------------------------------------------


def test_schema_versions_include_workspace_seq_index_migration_17(
    tmp_path: Path,
) -> None:
    conn = connect_sqlite(tmp_path / "vinctor.sqlite")
    init_sqlite_schema(conn)
    assert get_sqlite_schema_versions(conn) == tuple(range(1, 19))


def test_audit_events_workspace_index_exists(tmp_path: Path) -> None:
    conn = connect_sqlite(tmp_path / "vinctor.sqlite")
    init_sqlite_schema(conn)
    indexes = {
        row[1]
        for row in conn.execute("PRAGMA index_list(audit_events)").fetchall()
    }
    assert "idx_audit_events_workspace" in indexes


# ---------------------------------------------------------------------------
# Workspace scoping is mandatory (never cross-tenant).
# ---------------------------------------------------------------------------


def test_list_filtered_is_workspace_scoped(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "ws"):
        svc.audit_writer.write(_event(event_id="evt_main", workspace_id="ws_main"))
        svc.audit_writer.write(_event(event_id="evt_other", workspace_id="ws_other"))

        result = svc.list_filtered("ws_main")

        assert [e.event_id for e in result] == ["evt_main"]
        assert all(e.workspace_id == "ws_main" for e in result)


# ---------------------------------------------------------------------------
# Filters mirror the HTTP _event_matches semantics exactly.
# ---------------------------------------------------------------------------


def test_list_filtered_by_agent_id(tmp_path: Path) -> None:
    for i, svc in enumerate(_both_services(tmp_path / f"agent{0}")):
        svc.audit_writer.write(_event(event_id="evt_a", agent_id="agent_release"))
        svc.audit_writer.write(_event(event_id="evt_b", agent_id="agent_other"))

        result = svc.list_filtered("ws_main", agent_id="agent_release")

        assert [e.event_id for e in result] == ["evt_a"], i


def test_list_filtered_by_event_type(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "etype"):
        svc.audit_writer.write(_event(event_id="evt_a", event_type="action_denied"))
        svc.audit_writer.write(_event(event_id="evt_b", event_type="grant_issued"))

        result = svc.list_filtered("ws_main", event_type="grant_issued")

        assert [e.event_id for e in result] == ["evt_b"]


def test_list_filtered_by_validated_event_class(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "eclass"):
        svc.audit_writer.write(_event(event_id="evt_decision"))
        svc.audit_writer.write(_event(event_id="evt_control", event_class="control"))

        assert [
            event.event_id
            for event in svc.list_filtered("ws_main", event_class="control")
        ] == ["evt_control"]
        assert [
            event.event_id
            for event in svc.list_filtered("ws_main", event_class="decision")
        ] == ["evt_decision"]
        with pytest.raises(
            ValueError, match="event_class must be one of: control, decision"
        ):
            svc.list_filtered("ws_main", event_class="security")


def test_list_filtered_by_grant_ref(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "gref"):
        svc.audit_writer.write(_event(event_id="evt_a", grant_ref="grt_main"))
        svc.audit_writer.write(_event(event_id="evt_b", grant_ref="grt_other"))

        result = svc.list_filtered("ws_main", grant_ref="grt_other")

        assert [e.event_id for e in result] == ["evt_b"]


def test_list_filtered_by_boundary_id(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "bnd"):
        svc.audit_writer.write(_event(event_id="evt_a", boundary_id="bnd_x"))
        svc.audit_writer.write(_event(event_id="evt_b", boundary_id=None))

        result = svc.list_filtered("ws_main", boundary_id="bnd_x")

        assert [e.event_id for e in result] == ["evt_a"]


def test_list_filtered_by_request_id_matches_resource_or_grant_ref(
    tmp_path: Path,
) -> None:
    for svc in _both_services(tmp_path / "req"):
        # Matches because grant_ref == request_id.
        svc.audit_writer.write(
            _event(event_id="evt_gref", grant_ref="req_123", resource="other")
        )
        # Matches because resource == grant_request/{request_id}.
        svc.audit_writer.write(
            _event(
                event_id="evt_res",
                grant_ref="grt_main",
                resource="grant_request/req_123",
            )
        )
        # Does NOT match (only grant_id == request_id; HTTP rule ignores grant_id).
        svc.audit_writer.write(
            _event(
                event_id="evt_gid",
                grant_id="req_123",
                grant_ref="grt_main",
                resource="other",
            )
        )

        result = svc.list_filtered("ws_main", request_id="req_123")

        assert sorted(e.event_id for e in result) == ["evt_gref", "evt_res"]


def test_list_filtered_combines_filters_with_and(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "combo"):
        svc.audit_writer.write(
            _event(event_id="evt_match", agent_id="agent_release", event_type="x")
        )
        svc.audit_writer.write(
            _event(event_id="evt_wrong_agent", agent_id="agent_other", event_type="x")
        )
        svc.audit_writer.write(
            _event(event_id="evt_wrong_type", agent_id="agent_release", event_type="y")
        )

        result = svc.list_filtered(
            "ws_main", agent_id="agent_release", event_type="x"
        )

        assert [e.event_id for e in result] == ["evt_match"]


# ---------------------------------------------------------------------------
# Ordering + limit: the most-recent `limit` events, oldest-first within that
# window (identical to the old `[-limit:]` slice of insertion-ordered events).
# ---------------------------------------------------------------------------


def test_list_filtered_limit_returns_most_recent_window_oldest_first(
    tmp_path: Path,
) -> None:
    for svc in _both_services(tmp_path / "limit"):
        for i in range(5):
            svc.audit_writer.write(
                _event(event_id=f"evt_{i}", created_at=NOW + timedelta(seconds=i))
            )

        result = svc.list_filtered("ws_main", limit=2)

        # The two most recent events (evt_3, evt_4), oldest-first within the window.
        assert [e.event_id for e in result] == ["evt_3", "evt_4"]


def test_list_filtered_no_limit_returns_all_insertion_order(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "nolimit"):
        for i in range(3):
            svc.audit_writer.write(_event(event_id=f"evt_{i}"))

        result = svc.list_filtered("ws_main")

        assert [e.event_id for e in result] == ["evt_0", "evt_1", "evt_2"]


def test_audit_event_sequences_are_global_and_workspace_scoped(
    tmp_path: Path,
) -> None:
    for svc in _both_services(tmp_path / "sequence"):
        svc.audit_writer.write(_event(event_id="evt_first"))
        svc.audit_writer.write(
            _event(event_id="evt_other", workspace_id="ws_other")
        )
        svc.audit_writer.write(_event(event_id="evt_third"))

        sequences = svc.audit_event_sequences(
            "ws_main",
            ("evt_first", "evt_other", "evt_third"),
        )

        assert sequences == {"evt_first": 1, "evt_third": 3}


def test_list_filtered_cursor_bounds_keep_in_memory_sqlite_parity(
    tmp_path: Path,
) -> None:
    for svc in _both_services(tmp_path / "cursor"):
        for index in range(5):
            svc.audit_writer.write(
                _event(
                    event_id=f"evt_{index}",
                    grant_ref="grt_cursor",
                    created_at=NOW + timedelta(seconds=index),
                )
            )
        svc.audit_writer.write(
            _event(event_id="evt_other", grant_ref="grt_other")
        )

        newest = svc.list_filtered("ws_main", grant_ref="grt_cursor", limit=3)
        svc.audit_writer.write(
            _event(event_id="evt_concurrent", grant_ref="grt_cursor")
        )
        older = svc.list_filtered(
            "ws_main",
            grant_ref="grt_cursor",
            snapshot_event_id="evt_4",
            before_event_id="evt_3",
            limit=3,
        )

        assert [event.event_id for event in newest] == ["evt_2", "evt_3", "evt_4"]
        assert [event.event_id for event in older] == ["evt_0", "evt_1", "evt_2"]


@pytest.mark.parametrize(
    ("snapshot_event_id", "before_event_id"),
    [
        ("evt_unknown", None),
        ("evt_other", None),
        ("evt_snapshot", "evt_unknown"),
        ("evt_snapshot", "evt_other"),
        ("evt_early", "evt_newer"),
        (None, "evt_early"),
    ],
)
def test_list_filtered_rejects_invalid_cursor_without_disclosure(
    tmp_path: Path,
    snapshot_event_id: str | None,
    before_event_id: str | None,
) -> None:
    # Given: ordered same-workspace events plus a cursor owned by another workspace.
    for svc in _both_services(tmp_path / "cursor_invalid"):
        svc.audit_writer.write(_event(event_id="evt_early"))
        svc.audit_writer.write(_event(event_id="evt_snapshot"))
        svc.audit_writer.write(_event(event_id="evt_newer"))
        svc.audit_writer.write(
            _event(event_id="evt_other", workspace_id="ws_other")
        )

        # When: an invalid cursor pair is applied directly at the storage seam.
        with pytest.raises(ValueError, match="^invalid cursor$"):
            svc.list_filtered(
                "ws_main",
                snapshot_event_id=snapshot_event_id,
                before_event_id=before_event_id,
            )

        # Then: every invalid class produces the same coarse error.


def test_list_filtered_matches_legacy_python_filter(tmp_path: Path) -> None:
    """The SQL pushdown returns exactly what the old in-Python filter produced."""
    for svc in _both_services(tmp_path / "legacy"):
        for i in range(6):
            svc.audit_writer.write(
                _event(
                    event_id=f"evt_{i}",
                    event_type="action_denied" if i % 2 == 0 else "grant_issued",
                    created_at=NOW + timedelta(seconds=i),
                )
            )

        # Legacy behavior: read all (workspace-scoped, insertion order), filter in
        # Python, then take the last `limit`.
        legacy = [
            e
            for e in svc.audit_events
            if e.workspace_id == "ws_main" and e.event_type == "action_denied"
        ][-2:]

        result = svc.list_filtered("ws_main", event_type="action_denied", limit=2)

        assert [e.event_id for e in result] == [e.event_id for e in legacy]


# ---------------------------------------------------------------------------
# SQLite must not load the whole table: a large table with a small limit
# materializes only `limit` rows (parameterized WHERE/ORDER/LIMIT in SQL).
# ---------------------------------------------------------------------------


class _RecordingConnection(sqlite3.Connection):
    """A sqlite3.Connection that records every (sql, params) it executes.

    Subclassing is the supported way to intercept ``execute`` since the C-level
    ``execute`` attribute is read-only on a plain Connection instance.
    """

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.calls: list[tuple[str, tuple]] = []

    def execute(self, sql: str, params: tuple = ()):  # type: ignore[override]
        self.calls.append((sql, params))
        return super().execute(sql, params)


def _recording_service(tmp_path: Path) -> SQLiteV1Service:
    conn = connect_sqlite(
        tmp_path / "vinctor.sqlite", factory=_RecordingConnection
    )
    return SQLiteV1Service(conn)


def test_sqlite_list_filtered_does_not_load_whole_table(tmp_path: Path) -> None:
    svc = _recording_service(tmp_path)
    for i in range(500):
        svc.audit_writer.write(
            _event(event_id=f"evt_{i}", created_at=NOW + timedelta(seconds=i))
        )

    conn: _RecordingConnection = svc.conn  # type: ignore[assignment]
    conn.calls.clear()
    result = svc.list_filtered("ws_main", limit=3)

    select_calls = [
        (sql, params)
        for sql, params in conn.calls
        if "FROM audit_events" in sql and "SELECT event_json" in sql
    ]
    assert select_calls, "expected a SELECT against audit_events"
    sql, _params = select_calls[-1]
    # The SQL itself does the limiting (no full-table scan into Python).
    assert "LIMIT" in sql.upper()
    assert "ORDER BY seq DESC" in sql
    assert "WHERE" in sql.upper() and "workspace_id = ?" in sql
    assert len(result) == 3


def test_sqlite_paged_audit_query_uses_workspace_seq_index_without_temp_sort(
    tmp_path: Path,
) -> None:
    # Given: enough workspace events for a bounded continuation page.
    svc = _recording_service(tmp_path)
    for index in range(205):
        svc.audit_writer.write(_event(event_id=f"evt_{index:03d}"))

    # When: the real list implementation builds and executes a continuation query.
    conn: _RecordingConnection = svc.conn  # type: ignore[assignment]
    conn.calls.clear()
    svc.list_filtered(
        "ws_main",
        snapshot_event_id="evt_204",
        before_event_id="evt_105",
        limit=100,
    )
    sql, params = next(
        (sql, params)
        for sql, params in reversed(conn.calls)
        if "SELECT event_json FROM audit_events" in sql
    )
    plan = conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall()

    # Then: SQLite walks the workspace+sequence index and performs no temp sort.
    details = [row[3] for row in plan]
    assert any(
        "idx_audit_events_workspace_seq" in detail for detail in details
    ), details
    assert all("USE TEMP B-TREE" not in detail for detail in details)


def test_sqlite_list_filtered_uses_parameterized_sql(tmp_path: Path) -> None:
    """All filters must be bound parameters (no string interpolation of values)."""
    svc = _recording_service(tmp_path)
    svc.audit_writer.write(_event(event_id="evt_a"))

    conn: _RecordingConnection = svc.conn  # type: ignore[assignment]
    conn.calls.clear()
    svc.list_filtered(
        "ws_main",
        event_type="'; DROP TABLE audit_events; --",
        grant_ref="grt_main",
        agent_id="agent_release",
        limit=5,
    )

    select_calls = [
        (sql, params)
        for sql, params in conn.calls
        if "FROM audit_events" in sql and "SELECT event_json" in sql
    ]
    assert select_calls, "expected a SELECT against audit_events"
    sql, params = select_calls[-1]
    # The injection string must travel as a bound parameter, never inlined.
    assert "DROP TABLE" not in sql
    assert "'; DROP TABLE audit_events; --" in params
    # Table survives.
    assert svc.conn.execute(
        "SELECT COUNT(*) FROM audit_events"
    ).fetchone()[0] == 1


# ---------------------------------------------------------------------------
# Security-field filters (additive): reason_code, enforcing_principal,
# subject_token_verified. Absent filter = unchanged behavior; each narrows to the
# matching subset on BOTH backends.
# ---------------------------------------------------------------------------


def test_list_filtered_by_reason_code(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "rcode"):
        svc.audit_writer.write(
            replace(_event(event_id="evt_a"), reason_code="boundary_unregistered")
        )
        svc.audit_writer.write(
            replace(_event(event_id="evt_b"), reason_code="agent_key_invalid")
        )
        svc.audit_writer.write(_event(event_id="evt_none"))

        result = svc.list_filtered("ws_main", reason_code="boundary_unregistered")

        assert [e.event_id for e in result] == ["evt_a"]
        # Absent filter: unchanged behavior (all events, insertion order).
        assert [e.event_id for e in svc.list_filtered("ws_main")] == [
            "evt_a",
            "evt_b",
            "evt_none",
        ]


def test_list_filtered_by_enforcing_principal(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "principal"):
        svc.audit_writer.write(
            replace(_event(event_id="evt_pep"), enforcing_principal="pep_git_host")
        )
        svc.audit_writer.write(
            replace(_event(event_id="evt_other"), enforcing_principal="pep_mail")
        )
        svc.audit_writer.write(_event(event_id="evt_none"))

        result = svc.list_filtered("ws_main", enforcing_principal="pep_git_host")

        assert [e.event_id for e in result] == ["evt_pep"]
        assert [e.event_id for e in svc.list_filtered("ws_main")] == [
            "evt_pep",
            "evt_other",
            "evt_none",
        ]


def test_list_filtered_by_subject_token_verified_true_and_false(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "proven"):
        svc.audit_writer.write(
            replace(
                _event(event_id="evt_proven"),
                subject_token_verified=True,
                token_id="tok_1",
            )
        )
        svc.audit_writer.write(_event(event_id="evt_unproven"))

        assert [
            e.event_id for e in svc.list_filtered("ws_main", subject_token_verified=True)
        ] == ["evt_proven"]
        assert [
            e.event_id for e in svc.list_filtered("ws_main", subject_token_verified=False)
        ] == ["evt_unproven"]
        # Tri-state: None (absent) applies no identity filter.
        assert [e.event_id for e in svc.list_filtered("ws_main")] == [
            "evt_proven",
            "evt_unproven",
        ]


def test_list_filtered_security_filters_combine_with_and(tmp_path: Path) -> None:
    for svc in _both_services(tmp_path / "seccombo"):
        svc.audit_writer.write(
            replace(
                _event(event_id="evt_match"),
                enforcing_principal="pep_git_host",
                subject_token_verified=True,
            )
        )
        svc.audit_writer.write(
            replace(_event(event_id="evt_unproven"), enforcing_principal="pep_git_host")
        )

        result = svc.list_filtered(
            "ws_main", enforcing_principal="pep_git_host", subject_token_verified=True
        )

        assert [e.event_id for e in result] == ["evt_match"]


def test_sqlite_security_filters_use_parameterized_sql(tmp_path: Path) -> None:
    """The new filter values must be bound parameters, never inlined into SQL."""
    svc = _recording_service(tmp_path)
    svc.audit_writer.write(_event(event_id="evt_a"))

    conn: _RecordingConnection = svc.conn  # type: ignore[assignment]
    conn.calls.clear()
    svc.list_filtered(
        "ws_main",
        reason_code="'; DROP TABLE audit_events; --",
        enforcing_principal="'; DROP TABLE audit_events; --",
        subject_token_verified=True,
    )

    select_calls = [
        (sql, params)
        for sql, params in conn.calls
        if "FROM audit_events" in sql and "SELECT event_json" in sql
    ]
    assert select_calls, "expected a SELECT against audit_events"
    sql, params = select_calls[-1]
    assert "DROP TABLE" not in sql
    assert params.count("'; DROP TABLE audit_events; --") == 2
    # Table survives.
    assert svc.conn.execute(
        "SELECT COUNT(*) FROM audit_events"
    ).fetchone()[0] == 1
