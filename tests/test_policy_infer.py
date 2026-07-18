from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest
import yaml

from vinctor_core.models import AuditEvent
from vinctor_service.cli import run_vinctor
from vinctor_service.policy_infer import infer_policy_document
from vinctor_service.sqlite import SQLiteAuditWriter, init_sqlite_schema
from vinctor_service.sqlite_txn import connect_sqlite


def _event(
    *,
    agent_id: str,
    action: str,
    resource: str,
    decision: str,
    created_at: datetime,
    workspace_id: str = "ws",
    event_type: str | None = None,
) -> AuditEvent:
    resolved_event_type = event_type or (
        "action_permitted" if decision == "permit" else "action_denied"
    )
    return AuditEvent(
        event_id=f"evt_{agent_id}_{action}_{resource}_{created_at.isoformat()}",
        event_type=resolved_event_type,
        decision=decision,
        reason=resolved_event_type,
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


def test_proposes_exact_scopes_from_mapped_observations_only():
    events = [
        _event(
            agent_id="a1",
            action="read",
            resource="repo/feature/readme",
            decision="permit",
            event_type="action_observed",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="",
            resource="",
            decision="permit",
            event_type="action_unmapped",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
    ]

    doc = infer_policy_document(events, agent_id="a1")

    assert [s["scope"] for s in doc["proposed"]["scopes"]] == [
        "read:repo/feature/readme"
    ]
    assert doc["proposed"]["scopes"][0]["evidence"] == {
        "enforced": 0,
        "observed": 1,
        "simulated": 0,
    }


def test_infer_reports_evidence_sources_and_simulation_outcomes():
    events = [
        _event(
            agent_id="a1",
            action="read",
            resource="repo/feature/readme",
            decision="permit",
            event_type="action_observed",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="read",
            resource="repo/feature/readme",
            decision="permit",
            event_type="action_would_permit",
            created_at=datetime(2026, 7, 2, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="write",
            resource="repo/other/readme",
            decision="deny",
            event_type="action_would_deny",
            created_at=datetime(2026, 7, 2, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="",
            resource="",
            decision="permit",
            event_type="action_unmapped",
            created_at=datetime(2026, 7, 2, tzinfo=UTC),
        ),
    ]

    doc = infer_policy_document(events, agent_id="a1")

    scope = doc["proposed"]["scopes"][0]
    assert scope["count"] == 2
    assert scope["evidence"] == {
        "enforced": 0,
        "observed": 1,
        "simulated": 1,
    }
    assert doc["proposed"]["evidence_summary"] == {
        "enforced_permit": 0,
        "observed_mapped": 1,
        "observed_unmapped": 1,
        "blocked_unmapped": 0,
        "simulated_permit": 1,
        "simulated_deny": 1,
    }


def test_blocked_unmapped_counts_as_evidence_but_never_proposes_scopes():
    events = [
        _event(
            agent_id="a1",
            action="read",
            resource="repo/feature/readme",
            decision="permit",
            event_type="action_observed",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="",
            resource="",
            decision="deny",
            event_type="action_blocked_unmapped",
            created_at=datetime(2026, 7, 2, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="",
            resource="",
            decision="deny",
            event_type="action_blocked_unmapped",
            created_at=datetime(2026, 7, 3, tzinfo=UTC),
        ),
        # Another agent's blocked-unmapped event stays out of a1's evidence.
        _event(
            agent_id="a2",
            action="",
            resource="",
            decision="deny",
            event_type="action_blocked_unmapped",
            created_at=datetime(2026, 7, 3, tzinfo=UTC),
        ),
    ]

    doc = infer_policy_document(events, agent_id="a1", include_denied=True)

    assert doc["proposed"]["evidence_summary"]["blocked_unmapped"] == 2
    # Blocked-unmapped rows carry no action/resource: they must never surface
    # as proposed scopes nor as candidates_from_denied.
    assert [s["scope"] for s in doc["proposed"]["scopes"]] == [
        "read:repo/feature/readme"
    ]
    assert doc["proposed"]["candidates_from_denied"] == []


def test_infer_warns_only_on_scopes_backed_entirely_by_observed_evidence():
    events = [
        _event(
            agent_id="a1",
            action="read",
            resource="repo/observed/readme",
            decision="permit",
            event_type="action_observed",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="read",
            resource="repo/enforced/readme",
            decision="permit",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="read",
            resource="repo/simulated/readme",
            decision="permit",
            event_type="action_would_permit",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="read",
            resource="repo/mixed/readme",
            decision="permit",
            event_type="action_observed",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        ),
        _event(
            agent_id="a1",
            action="read",
            resource="repo/mixed/readme",
            decision="permit",
            created_at=datetime(2026, 7, 2, tzinfo=UTC),
        ),
    ]

    doc = infer_policy_document(events, agent_id="a1")

    scopes = {entry["scope"]: entry for entry in doc["proposed"]["scopes"]}
    assert scopes["read:repo/observed/readme"]["warning"] == (
        "observed-only evidence; unverified agent self-report"
    )
    assert "warning" not in scopes["read:repo/enforced/readme"]
    assert "warning" not in scopes["read:repo/simulated/readme"]
    assert "warning" not in scopes["read:repo/mixed/readme"]


def test_infer_ignores_non_action_permit_events():
    events = [
        _event(
            agent_id="a1",
            action="write",
            resource="repo/feature/readme",
            decision="permit",
            event_type="grant_issued",
            created_at=datetime(2026, 7, 1, tzinfo=UTC),
        )
    ]

    doc = infer_policy_document(events, agent_id="a1")

    assert doc["proposed"]["scopes"] == []


def test_min_observations_filters_before_wildcard_generalization():
    events = [
        _event(agent_id="a1", action="read", resource="repo/feature/a",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="read", resource="repo/feature/b",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="read", resource="repo/feature/b",
               decision="permit", created_at=datetime(2026, 7, 2, tzinfo=UTC)),
    ]

    doc = infer_policy_document(
        events,
        agent_id="a1",
        generalize=True,
        min_observations=2,
    )

    assert [entry["scope"] for entry in doc["proposed"]["scopes"]] == [
        "read:repo/feature/b"
    ]
    assert doc["proposed"]["minimum_observations"] == 2


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
    conn = connect_sqlite(db_path)
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


def test_cli_policy_infer_renders_observed_only_warning(tmp_path: Path):
    db_path = tmp_path / "vinctor.sqlite"
    _seed(
        db_path,
        [
            _event(
                agent_id="a1",
                action="read",
                resource="repo/feature/readme",
                decision="permit",
                event_type="action_observed",
                created_at=datetime(2026, 7, 1, tzinfo=UTC),
            )
        ],
    )
    stdout = StringIO()

    status = run_vinctor(
        ["--db", str(db_path), "operator", "policy", "infer", "--agent", "a1"],
        stdout=stdout,
        stderr=StringIO(),
    )

    assert status == 0
    doc = yaml.safe_load(stdout.getvalue())
    assert doc["proposed"]["scopes"][0]["warning"] == (
        "observed-only evidence; unverified agent self-report"
    )


def test_cli_policy_infer_surfaces_pep_blocked_unmapped_evidence(tmp_path: Path):
    """A PEP that blocks unmapped actions (F7) shows up in policy infer evidence."""
    db_path = tmp_path / "vinctor.sqlite"
    _seed(
        db_path,
        [
            _event(
                agent_id="a1",
                action="read",
                resource="repo/feature/readme",
                decision="permit",
                event_type="action_observed",
                created_at=datetime(2026, 7, 1, tzinfo=UTC),
            ),
            _event(
                agent_id="a1",
                action="",
                resource="",
                decision="deny",
                event_type="action_blocked_unmapped",
                created_at=datetime(2026, 7, 2, tzinfo=UTC),
            ),
        ],
    )
    stdout = StringIO()

    status = run_vinctor(
        ["--db", str(db_path), "operator", "policy", "infer", "--agent", "a1"],
        stdout=stdout,
        stderr=StringIO(),
    )

    assert status == 0
    doc = yaml.safe_load(stdout.getvalue())
    assert doc["proposed"]["evidence_summary"]["blocked_unmapped"] == 1
    assert [s["scope"] for s in doc["proposed"]["scopes"]] == [
        "read:repo/feature/readme"
    ]


def test_cli_policy_infer_generalize_help_recommends_enforced_evidence(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        run_vinctor(["operator", "policy", "infer", "--help"])

    assert excinfo.value.code == 0
    help_text = capsys.readouterr().out
    assert "--generalize" in help_text
    assert "use enforced evidence, not observed-only data" in " ".join(help_text.split())


def test_cli_policy_infer_supports_min_observations(tmp_path: Path):
    db_path = tmp_path / "vinctor.sqlite"
    _seed(db_path, [
        _event(agent_id="a1", action="read", resource="repo/feature/once",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="read", resource="repo/feature/repeated",
               decision="permit", created_at=datetime(2026, 7, 1, tzinfo=UTC)),
        _event(agent_id="a1", action="read", resource="repo/feature/repeated",
               decision="permit", created_at=datetime(2026, 7, 2, tzinfo=UTC)),
    ])
    stdout = StringIO()

    status = run_vinctor(
        [
            "--db", str(db_path),
            "operator", "policy", "infer",
            "--agent", "a1",
            "--min-observations", "2",
        ],
        stdout=stdout,
        stderr=StringIO(),
    )

    assert status == 0
    doc = yaml.safe_load(stdout.getvalue())
    assert [entry["scope"] for entry in doc["proposed"]["scopes"]] == [
        "read:repo/feature/repeated"
    ]
