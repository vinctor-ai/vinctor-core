from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import yaml

from vinctor_core.models import AuditEvent
from vinctor_service.cli import run_vinctor
from vinctor_service.policy_infer import infer_policy_document
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema


def _event(
    *,
    agent_id: str,
    action: str,
    resource: str,
    decision: str,
    created_at: datetime,
    workspace_id: str = "ws",
) -> AuditEvent:
    event_type = "action_permitted" if decision == "permit" else "action_denied"
    return AuditEvent(
        event_id=f"evt_{agent_id}_{action}_{resource}_{created_at.isoformat()}",
        event_type=event_type,
        decision=decision,
        reason=event_type,
        workspace_id=workspace_id,
        agent_id=agent_id,
        grant_id="g",
        grant_ref="gr",
        action=action,
        resource=resource,
        scope_attempted=f"{action}:{resource}",
        scope_matched=f"{action}:{resource}" if decision == "permit" else None,
        boundary_id=None,
        runtime=None,
        boundary_type=None,
        created_at=created_at,
    )


# ── infer_policy_document (pure logic) ──────────────────────────────────────


def test_proposes_exact_scopes_from_permitted_events_for_the_agent():
    events = [
        _event(agent_id="a1", action="read", resource="repo/feature/readme",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="send", resource="net/external/x",
               decision="deny", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a2", action="read", resource="repo/other/x",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
    ]
    doc = infer_policy_document(events, agent_id="a1")
    assert doc["proposed"]["apply"] is False
    assert doc["proposed"]["agent_id"] == "a1"
    assert [s["scope"] for s in doc["proposed"]["scopes"]] == ["read:repo/feature/readme"]
    assert "candidates_from_denied" not in doc["proposed"]


def test_since_and_until_window_filters_events():
    events = [
        _event(agent_id="a1", action="read", resource="repo/feature/a",
               decision="permit", created_at=datetime(2026, 6, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="read", resource="repo/feature/b",
               decision="permit", created_at=datetime(2026, 7, 2, tzinfo=UTC)),
        _event(agent_id="a1", action="read", resource="repo/feature/c",
               decision="permit", created_at=datetime(2026, 8, 1, tzinfo=UTC)),
    ]
    doc = infer_policy_document(
        events, agent_id="a1",
        since="2026-07-01T00:00:00+00:00", until="2026-07-31T00:00:00+00:00",
    )
    assert [s["scope"] for s in doc["proposed"]["scopes"]] == ["read:repo/feature/b"]


def test_generalize_flows_through_with_covers_count_and_last_seen():
    events = [
        _event(agent_id="a1", action="read", resource="repo/feature/a",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="read", resource="repo/feature/b",
               decision="permit", created_at=datetime(2026, 7, 3, tzinfo=UTC)),
    ]
    doc = infer_policy_document(events, agent_id="a1", generalize=True)
    scopes = doc["proposed"]["scopes"]
    assert [s["scope"] for s in scopes] == ["read:repo/feature/*"]
    assert scopes[0]["covers"] == ["read:repo/feature/a", "read:repo/feature/b"]
    assert scopes[0]["count"] == 2
    assert scopes[0]["last_seen"] == "2026-07-03T00:00:00+00:00"


def test_include_denied_adds_separate_candidates_never_merged():
    events = [
        _event(agent_id="a1", action="read", resource="repo/feature/a",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="send", resource="net/external/x",
               decision="deny", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
    ]
    doc = infer_policy_document(events, agent_id="a1", include_denied=True)
    assert [s["scope"] for s in doc["proposed"]["scopes"]] == ["read:repo/feature/a"]
    assert [s["scope"] for s in doc["proposed"]["candidates_from_denied"]] == [
        "send:net/external/x"
    ]


# ── CLI wiring ──────────────────────────────────────────────────────────────


def _seed(db_path: Path, events: list[AuditEvent]) -> None:
    conn = sqlite3.connect(db_path)
    init_sqlite_schema(conn)
    writer = SQLiteAuditWriter(conn)
    for event in events:
        writer.write(event)
    conn.close()


def test_cli_policy_infer_emits_yaml_proposal(tmp_path: Path):
    db_path = tmp_path / "vinctor.sqlite"
    _seed(db_path, [
        _event(agent_id="a1", action="read", resource="repo/feature/readme",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="send", resource="net/external/x",
               decision="deny", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
    ])
    stdout = StringIO()
    status = run_vinctor(
        ["--db", str(db_path), "operator", "policy", "infer", "--agent", "a1"],
        stdout=stdout,
        stderr=StringIO(),
    )
    assert status == 0
    doc = yaml.safe_load(stdout.getvalue())
    assert doc["proposed"]["apply"] is False
    assert [s["scope"] for s in doc["proposed"]["scopes"]] == ["read:repo/feature/readme"]
