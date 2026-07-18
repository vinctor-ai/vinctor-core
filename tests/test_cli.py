from __future__ import annotations

import contextlib
import importlib.metadata
import json
import shutil
import sqlite3
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from threading import Thread

import pytest
import yaml

from vinctor_service import (
    GrantRequestCreateRequest,
    SQLiteV1Service,
    V1DelegatedEnforceRequest,
)
from vinctor_service.cli import (
    EXIT_AUTH,
    EXIT_USAGE,
    CliError,
    _request_json,
    run_vinctor,
)
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.models import GrantIssueRequest
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def test_vinctor_cli_agent_request_operator_evaluate_and_enforce(
    tmp_path: Path,
) -> None:
    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        common = _common_args(handle, json_output=True)
        rule = _run(
            [
                *common,
                "operator",
                "rules",
                "create",
                "--name",
                "CI auto approval",
                "--target-agent-id",
                "agent_runner",
                "--scope",
                "execute:ci/test",
                "--max-ttl",
                "30m",
            ]
        )
        created = _run(
            [
                *common,
                "agent",
                "requests",
                "create",
                "--scope",
                "execute:ci/test",
                "--ttl",
                "15m",
                "--reason",
                "run CI validation",
            ]
        )
        evaluated = _run(
            [
                *common,
                "operator",
                "requests",
                "evaluate",
                created["request_id"],
            ]
        )
        enforced = _run(
            [
                *common,
                "agent",
                "enforce",
                "--grant-ref",
                evaluated["issued_grant_ref"],
                "--action",
                "execute",
                "--resource",
                "ci/test",
            ]
        )

        assert rule["status"] == "active"
        assert created["routing_hint"] == "auto_approval_available"
        assert evaluated["status"] == "approved"
        assert enforced["decision"] == "permit"
    finally:
        _stop_service(handle)


def test_vinctor_cli_agent_enforce_json_deny_emits_single_object(tmp_path: Path) -> None:
    from vinctor_service.cli import EXIT_DENIED

    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        common = _common_args(handle, json_output=True)
        stdout, stderr = StringIO(), StringIO()
        status = run_vinctor(
            [
                *common,
                "agent",
                "enforce",
                "--grant-ref",
                handle.grant_ref,
                "--action",
                "write",
                "--resource",
                "repo/secret",
            ],
            stdout=stdout,
            stderr=stderr,
        )

        assert status == EXIT_DENIED
        # stdout holds exactly one JSON object: the deny decision.
        decision = json.loads(stdout.getvalue())
        assert decision["decision"] == "deny"
        # In JSON mode the deny case must not also print a second JSON object to stderr.
        assert stderr.getvalue() == ""
    finally:
        _stop_service(handle)


def test_vinctor_cli_agent_enforce_output_is_no_disclosure(tmp_path: Path) -> None:
    # Agent-facing no-disclosure: `agent enforce` output (JSON and text) may
    # carry only the decision, a coarse reason code, and the audit_event_id --
    # never the grant_id/agent_id or a detailed reason naming the classified
    # scope or the grant. (The text summary echoing the caller's own --action/
    # --resource arguments is local input echo, not server disclosure.)
    from vinctor_service.cli import EXIT_DENIED

    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        deny_args = [
            "agent",
            "enforce",
            "--grant-ref",
            handle.grant_ref,
            "--action",
            "write",
            "--resource",
            "repo/PROBE_TARGET",
        ]

        json_out, json_err = StringIO(), StringIO()
        status = run_vinctor(
            [*_common_args(handle, json_output=True), *deny_args],
            stdout=json_out,
            stderr=json_err,
        )
        assert status == EXIT_DENIED
        decision = json.loads(json_out.getvalue())
        assert set(decision) == {"decision", "error", "reason", "audit_event_id"}
        assert decision["decision"] == "deny"
        assert decision["reason"] == "action_denied"
        for leak in ("grnt_", "PROBE_TARGET"):
            assert leak not in json_out.getvalue()
            assert leak not in json_err.getvalue()

        text_out, text_err = StringIO(), StringIO()
        status = run_vinctor(
            [*_common_args(handle, json_output=False), *deny_args],
            stdout=text_out,
            stderr=text_err,
        )
        assert status == EXIT_DENIED
        assert "error: action_denied" in text_err.getvalue()
        for stream in (text_out.getvalue(), text_err.getvalue()):
            assert "grnt_" not in stream
            assert "ci/test" not in stream  # the grant's scope stays undisclosed

        permit_out, permit_err = StringIO(), StringIO()
        status = run_vinctor(
            [
                *_common_args(handle, json_output=True),
                "agent",
                "enforce",
                "--grant-ref",
                handle.grant_ref,
                "--action",
                "execute",
                "--resource",
                "ci/test",
            ],
            stdout=permit_out,
            stderr=permit_err,
        )
        assert status == 0
        permitted = json.loads(permit_out.getvalue())
        assert set(permitted) == {"decision", "audit_event_id"}
        assert permitted["decision"] == "permit"
        assert "grnt_" not in permit_out.getvalue()
    finally:
        _stop_service(handle)


def test_vinctor_cli_agent_token_mint(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("write:repo/feature/*",))
    try:
        common = _common_args(handle, json_output=True)
        result = _run(
            [
                *common,
                "agent",
                "token",
                "mint",
                "--grant-ref",
                handle.grant_ref,
                "--audience",
                "pep_git_host",
            ]
        )
        assert result["token"].startswith("vat_")
        assert result["token_id"].startswith("vtk_")
        assert "expires_at" in result
    finally:
        _stop_service(handle)


def test_vinctor_cli_agent_token_mint_with_binding(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("write:repo/feature/*",))
    try:
        common = _common_args(handle, json_output=True)
        result = _run(
            [
                *common,
                "agent",
                "token",
                "mint",
                "--grant-ref",
                handle.grant_ref,
                "--audience",
                "pep_git_host",
                "--action",
                "write",
                "--resource",
                "repo/feature/readme",
            ]
        )
        assert result["token"].startswith("vat_")
        assert result["token_id"].startswith("vtk_")
    finally:
        _stop_service(handle)


def test_vinctor_cli_agent_token_mint_with_pop(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("write:repo/feature/*",))
    try:
        common = _common_args(handle, json_output=True)
        result = _run(
            [
                *common,
                "agent",
                "token",
                "mint",
                "--grant-ref",
                handle.grant_ref,
                "--audience",
                "pep_git_host",
                "--pop",
            ]
        )
        assert result["token"].startswith("vat_")
        assert isinstance(result["pop_secret"], str) and result["pop_secret"] != ""
    finally:
        _stop_service(handle)


def test_vinctor_cli_manual_review_flow_and_audit_filter(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("write:repo/vinctor-core/*",))
    try:
        common = _common_args(handle, json_output=True)
        created = _run(
            [
                *common,
                "agent",
                "requests",
                "create",
                "--scope",
                "write:repo/vinctor-core/README.md",
                "--ttl",
                "30m",
                "--reason",
                "edit core README",
                "--task-id",
                "task-docs",
                "--session-id",
                "session-123",
                "--runtime",
                "codex",
                "--repo",
                "vinctor-core",
                "--worktree",
                "feature/docs",
            ]
        )
        evaluated = _run(
            [
                *common,
                "operator",
                "requests",
                "evaluate",
                created["request_id"],
            ]
        )
        status = _run(
            [
                *common,
                "agent",
                "requests",
                "status",
                created["request_id"],
            ]
        )
        queue = _run(
            [
                *common,
                "operator",
                "requests",
                "list",
                "--status",
                "pending",
            ]
        )
        inbox = _run([*common, "operator", "requests", "inbox"])
        approved = _run(
            [
                *common,
                "operator",
                "requests",
                "approve",
                created["request_id"],
                "--reason",
                "manual operator review",
            ]
        )
        audit = _run(
            [
                *common,
                "operator",
                "audit",
                "list",
                "--request-id",
                created["request_id"],
            ]
        )
        timeline = _run(
            [
                *common,
                "operator",
                "requests",
                "timeline",
                created["request_id"],
            ]
        )

        assert created["routing_hint"] == "manual_review_required"
        assert created["routing_reason"] == "no_matching_rule"
        assert created["task_id"] == "task-docs"
        assert created["repo"] == "vinctor-core"
        assert evaluated["status"] == "pending"
        assert evaluated["auto_approval"]["reason"] == "no_matching_rule"
        assert status["status"] == "pending"
        assert "decided_by" not in status
        assert status["task_id"] == "task-docs"
        assert queue["grant_requests"][0]["queue_reason"] == "no_matching_rule"
        assert inbox["grant_requests"][0]["risk"] == "medium"
        assert inbox["grant_requests"][0]["recommended_action"] == "manual_review"
        assert approved["status"] == "approved"
        assert [event["event_type"] for event in timeline["timeline"]] == [
            "grant_requested",
            "grant_issued",
            "grant_request_approved",
        ]
        assert [event["event_type"] for event in audit["audit_events"]] == [
            "grant_requested",
            "grant_request_approved",
        ]
    finally:
        _stop_service(handle)


def test_vinctor_cli_requests_text_display_no_doubled_metadata_or_stale_routing(
    tmp_path: Path,
) -> None:
    handle = _start_service(tmp_path, scopes=("write:repo/vinctor-core/*",))
    try:
        common = _common_args(handle, json_output=True)
        created = _run(
            [
                *common,
                "agent",
                "requests",
                "create",
                "--scope",
                "write:repo/vinctor-core/README.md",
                "--ttl",
                "30m",
                "--reason",
                "edit core README",
                "--task-id",
                "task-docs",
            ]
        )
        request_id = created["request_id"]
        text_common = _common_args(handle, json_output=False)

        inbox_text = _run_text([*text_common, "operator", "requests", "inbox"])
        assert "metadata=metadata=" not in inbox_text
        assert "metadata=task_id=task-docs" in inbox_text

        _run(
            [
                *common,
                "operator",
                "requests",
                "approve",
                request_id,
                "--reason",
                "manual operator review",
            ]
        )

        view_text = _run_text(
            [*text_common, "operator", "requests", "view", request_id]
        )
        assert "status=approved" in view_text
        assert "routing=" not in view_text
        assert "queue_reason=" not in view_text
    finally:
        _stop_service(handle)


def test_vinctor_cli_audit_export_writes_workspace_jsonl(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    export_path = tmp_path / "audit.jsonl"
    _seed_rejected_request_audit(db_path)

    output = _run_text(
        [
            "--db",
            str(db_path),
            "--workspace-key",
            "wsk_demo",
            "operator",
            "audit",
            "export",
            "--format",
            "jsonl",
            "--file",
            str(export_path),
        ]
    )

    lines = export_path.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    forbidden = {"raw_tool_input", "raw_command", "prompt", "model_facing_reason"}
    assert "exported audit events count=2" in output
    assert [(event["event_type"], event["decision"]) for event in events] == [
        ("grant_requested", "permit"),
        ("grant_request_rejected", "deny"),
    ]
    assert all(event.keys().isdisjoint(forbidden) for event in events)


def test_vinctor_cli_audit_export_requires_valid_workspace_key(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_rejected_request_audit(db_path)

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        [
            "--db",
            str(db_path),
            "--workspace-key",
            "wsk_missing",
            "operator",
            "audit",
            "export",
            "--format",
            "jsonl",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 4
    assert "valid workspace or auditor key is required" in stderr.getvalue()
    assert stdout.getvalue() == ""


def test_vinctor_cli_audit_export_accepts_read_only_auditor_key(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_rejected_request_audit(db_path)
    conn = connect_sqlite(db_path)
    SQLiteLocalKeyRepository(conn).create_auditor_key(
        workspace_id="ws_demo", raw_key="auk_demo", now=NOW
    )
    conn.close()

    output = _run_text(
        [
            "--db",
            str(db_path),
            "--auditor-key",
            "auk_demo",
            "operator",
            "audit",
            "export",
            "--format",
            "jsonl",
        ]
    )

    assert '"event_type": "grant_requested"' in output
    assert '"event_type": "grant_request_rejected"' in output


def test_vinctor_cli_auth_failures_requires_service_operator_key(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    SQLiteLocalKeyRepository(conn).create_service_operator_key(
        raw_key="sok_demo", now=NOW
    )
    service.record_auth_failure(surface="enforce", now=NOW)
    conn.close()

    result = _run(
        [
            "--json",
            "--db",
            str(db_path),
            "--service-operator-key",
            "sok_demo",
            "operator",
            "audit",
            "auth-failures",
        ]
    )

    assert len(result["auth_failures"]) == 1
    assert result["auth_failures"][0]["event_type"] == "auth_failed"
    assert result["auth_failures"][0]["workspace_id"] == ""


def test_vinctor_demo_check_runs_smoke_flow() -> None:
    result = _run(["--json", "demo", "check"])

    assert result["ok"] is True
    assert result["decision"] == "permit"
    assert result["audit_event_count"] == 6


def test_vinctor_demo_service_runs_user_facing_flow() -> None:
    result = _run(["--json", "demo", "service"])

    assert result["ok"] is True
    assert result["ci_decision"] == "permit"
    assert result["deploy_auto_approval_reason"] == "scope_outside_rule"
    assert result["deploy_decision"] == "permit"
    assert result["repo_core_decision"] == "permit"
    assert result["sibling_repo_status"] == 403
    assert result["sibling_repo_decision"] == "deny"


def test_vinctor_demo_block_shows_context_dependent_decisions() -> None:
    result = _run(["--json", "demo", "block"])

    assert result["ok"] is True
    assert result["audit_event_count"] == 3
    decisions = [beat["decision"] for beat in result["beats"]]
    assert decisions == ["permit", "deny", "deny"]
    # the allow and the first deny are the SAME action (send), separated only by
    # resource -- the "context decides, not a denylist" point.
    assert result["beats"][0]["action"] == result["beats"][1]["action"] == "send"
    assert all(beat["audit_event_id"] for beat in result["beats"])


def test_vinctor_local_env_formats_existing_values() -> None:
    stdout = StringIO()
    stderr = StringIO()

    status = run_vinctor(
        [
            "--endpoint",
            "http://127.0.0.1:8765",
            "--workspace-key",
            "wsk_demo",
            "--agent-key",
            "aak_demo",
            "--grant-ref",
            "grt_demo",
            "--boundary-id",
            "bnd_demo",
            "local",
            "env",
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 0, stderr.getvalue()
    assert 'export VINCTOR_ENDPOINT="http://127.0.0.1:8765"' in stdout.getvalue()
    assert 'export VINCTOR_BOUNDARY_ID="bnd_demo"' in stdout.getvalue()


def test_vinctor_local_env_writes_explicit_env_file(tmp_path: Path) -> None:
    env_path = tmp_path / ".vinctor.env"
    result = _run(
        [
            "--json",
            "--endpoint",
            "http://127.0.0.1:8765",
            "--workspace-key",
            "wsk_demo",
            "--agent-key",
            "aak_demo",
            "--grant-ref",
            "grt_demo",
            "local",
            "env",
            "--write-file",
            str(env_path),
        ]
    )

    assert result["env_file"] == str(env_path)
    assert 'export VINCTOR_AGENT_KEY="aak_demo"' in env_path.read_text(encoding="utf-8")


def test_vinctor_cli_policy_apply_export_and_service_info(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    policy_path = tmp_path / "policy.yaml"
    exported_path = tmp_path / "exported-policy.yaml"
    policy_path.write_text(
        """
version: 1
workspace_id: ws_demo
agent_bounds:
  - agent_id: agent_runner
    scopes:
      - execute:ci/test
      - write:repo/vinctor-core/*
auto_approval_rules:
  - rule_id: apr_ci
    name: CI auto approval
    target_agent_id: agent_runner
    allowed_scopes:
      - execute:ci/test
    max_ttl: 30m
""".strip(),
        encoding="utf-8",
    )

    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    applied = _run([*common, "operator", "policy", "apply", "--file", str(policy_path)])
    service_info = _run([*common, "operator", "service", "info"])
    exported = _run([*common, "operator", "policy", "export", "--file", str(exported_path)])

    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    bounds = service.scope_bounds_repository.get_bounds(
        workspace_id="ws_demo",
        agent_id="agent_runner",
    )
    rules = service.list_auto_approval_rules(workspace_id="ws_demo")
    exported_yaml = yaml.safe_load(exported_path.read_text(encoding="utf-8"))

    assert applied == {
        "bounds_set": 1,
        "policy_version": 1,
        "rules_created": 1,
        "rules_updated": 0,
        "workspace_id": "ws_demo",
    }
    assert service_info["schema_versions"] == list(range(1, 16))
    assert service_info["schema_version"] == 15
    assert exported["agent_bounds"] == 1
    assert exported["auto_approval_rules"] == 1
    assert bounds == ("execute:ci/test", "write:repo/vinctor-core/*")
    assert rules[0].rule_id == "apr_ci"
    assert rules[0].max_ttl_seconds == 1800
    exported_rule = exported_yaml["auto_approval_rules"][0]
    assert exported_rule["rule_id"] == "apr_ci"
    # Export uses the same `max_ttl` key the input did (round-trip symmetry),
    # as a string duration, and does NOT also emit max_ttl_seconds (apply
    # rejects setting both).
    assert exported_rule["max_ttl"] == "1800s"
    assert "max_ttl_seconds" not in exported_rule
    conn.close()

    # Re-applying the exported document is idempotent: same rule updated in
    # place (not re-created) and the stored TTL is unchanged.
    reapplied = _run([*common, "operator", "policy", "apply", "--file", str(exported_path)])
    assert reapplied["rules_updated"] == 1
    assert reapplied["rules_created"] == 0

    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    rules_after = service.list_auto_approval_rules(workspace_id="ws_demo")
    assert rules_after[0].max_ttl_seconds == 1800
    conn.close()


def test_vinctor_cli_policy_apply_export_require_boundary_round_trip(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    policy_path = tmp_path / "policy.yaml"
    exported_path = tmp_path / "exported-policy.yaml"
    policy_path.write_text(
        """
version: 1
workspace_id: ws_demo
require_boundary:
  workspace: true
  agents:
    - agent_runner
""".strip(),
        encoding="utf-8",
    )

    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    _run([*common, "operator", "policy", "apply", "--file", str(policy_path)])
    _run([*common, "operator", "policy", "export", "--file", str(exported_path)])

    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    repo = service.agent_enforcement_settings_repository
    assert repo.is_boundary_required(workspace_id="ws_demo", agent_id="agent_runner") is True
    assert repo.get_require_boundary_setting(workspace_id="ws_demo", agent_id="") is True
    conn.close()

    exported_yaml = yaml.safe_load(exported_path.read_text(encoding="utf-8"))
    assert exported_yaml["require_boundary"]["workspace"] is True
    assert "agent_runner" in exported_yaml["require_boundary"]["agents"]


def test_vinctor_cli_policy_versions_and_rollback(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    policy_path = tmp_path / "policy.yaml"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    policy_path.write_text(
        """
version: 1
workspace_id: ws_demo
agent_bounds:
  - agent_id: agent_a
    scopes: [read:repo/a]
""".strip(),
        encoding="utf-8",
    )
    _run([*common, "operator", "policy", "apply", "--file", str(policy_path)])
    policy_path.write_text(
        """
version: 1
workspace_id: ws_demo
agent_bounds:
  - agent_id: agent_b
    scopes: [write:repo/b]
""".strip(),
        encoding="utf-8",
    )
    _run([*common, "operator", "policy", "apply", "--file", str(policy_path)])

    listed = _run([*common, "operator", "policy", "versions"])
    rolled_back = _run(
        [*common, "operator", "policy", "rollback", "--version", "1"]
    )

    assert [item["version"] for item in listed["versions"]] == [1, 2]
    assert rolled_back == {
        "workspace_id": "ws_demo",
        "restored_version": 1,
        "policy_version": 3,
    }
    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    assert service.scope_bounds_repository.list_bounds_for_workspace("ws_demo") == (
        ("agent_a", ("read:repo/a",)),
    )
    conn.close()


def test_vinctor_cli_policy_apply_is_atomic_on_invalid_later_entry(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    policy_path = tmp_path / "bad-policy.yaml"
    # A valid bound for agent_a precedes an invalid-scope bound for agent_b.
    policy_path.write_text(
        """
version: 1
workspace_id: ws_demo
agent_bounds:
  - agent_id: agent_a
    scopes:
      - execute:ci/test
  - agent_id: agent_b
    scopes:
      - not-a-valid-scope
""".strip(),
        encoding="utf-8",
    )

    stdout, stderr = StringIO(), StringIO()
    status = run_vinctor(
        [
            "--db",
            str(db_path),
            "--workspace-id",
            "ws_demo",
            "operator",
            "policy",
            "apply",
            "--file",
            str(policy_path),
        ],
        stdout=stdout,
        stderr=stderr,
    )

    assert status != 0
    assert "invalid issuable scope bound" in stderr.getvalue()
    # Atomic apply: the valid earlier bound must NOT have been committed.
    conn = connect_sqlite(db_path)
    service = SQLiteV1Service(conn)
    assert (
        service.scope_bounds_repository.get_bounds(workspace_id="ws_demo", agent_id="agent_a")
        is None
    )
    conn.close()


def test_vinctor_cli_storage_backup_and_reset(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    backup_path = tmp_path / "backups" / "vinctor.backup.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path)]

    backup = _run([*common, "operator", "storage", "backup", "--output", str(backup_path)])
    reset = _run([*common, "operator", "storage", "reset", "--yes"])

    assert backup["output_path"] == str(backup_path)
    assert backup["bytes"] > 0
    assert backup["schema_versions"] == list(range(1, 16))
    assert reset == {
        "db_path": str(db_path),
        "reset": True,
        "schema_versions": list(range(1, 16)),
    }

    backup_conn = connect_sqlite(backup_path)
    reset_conn = connect_sqlite(db_path)
    try:
        backup_grant = SQLiteV1Service(
            backup_conn, initialize_schema=False
        ).grant_repository.get_by_ref("grt_seed")
        reset_grant = SQLiteV1Service(
            reset_conn, initialize_schema=False
        ).grant_repository.get_by_ref("grt_seed")
    finally:
        backup_conn.close()
        reset_conn.close()
    assert backup_grant is not None
    assert reset_grant is None


def test_vinctor_cli_storage_reset_requires_yes(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        ["--db", str(db_path), "operator", "storage", "reset"],
        stdout=stdout,
        stderr=stderr,
    )

    assert status != 0
    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_vinctor_cli_storage_backup_refuses_existing_without_force(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    backup_path = tmp_path / "vinctor.backup.sqlite"
    _seed_storage_db(db_path)
    backup_path.write_text("existing", encoding="utf-8")
    common = ["--json", "--db", str(db_path)]

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        [*common, "operator", "storage", "backup", "--output", str(backup_path)],
        stdout=stdout,
        stderr=stderr,
    )
    assert status != 0

    forced = _run(
        [*common, "operator", "storage", "backup", "--output", str(backup_path), "--force"]
    )
    assert forced["bytes"] > 0


def test_vinctor_cli_service_info_reports_schema(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    info = _run(["--json", "--db", str(db_path), "operator", "service", "info"])

    assert info["mode"] == "local"
    assert info["db_path"] == str(db_path)
    assert info["schema_version"] == 15
    assert info["schema_versions"] == list(range(1, 16))
    assert info["key_storage_mode"] == "sqlite_hashes"
    assert "host" in info
    assert "port" in info
    serialized = json.dumps(info).lower()
    assert "wsk_" not in serialized
    assert "aak_" not in serialized
    assert "key_hash" not in serialized


def test_vinctor_cli_service_info_graceful_without_db(tmp_path: Path) -> None:
    db_path = tmp_path / "missing.sqlite"

    info = _run(["--json", "--db", str(db_path), "operator", "service", "info"])

    assert info["schema_version"] is None
    assert info["schema_versions"] == []
    assert not db_path.exists()


def test_vinctor_cli_storage_restore_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    backup_path = tmp_path / "vinctor.backup.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path)]

    _run([*common, "operator", "storage", "backup", "--output", str(backup_path)])
    _run([*common, "operator", "storage", "reset", "--yes"])
    restore = _run(
        [*common, "operator", "storage", "restore", "--input", str(backup_path), "--yes"]
    )

    assert restore == {
        "db_path": str(db_path),
        "input_path": str(backup_path),
        "restored": True,
        "schema_versions": list(range(1, 16)),
    }
    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_vinctor_cli_storage_restore_requires_yes(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    backup_path = tmp_path / "vinctor.backup.sqlite"
    _seed_storage_db(db_path)
    _run(
        [
            "--json",
            "--db",
            str(db_path),
            "operator",
            "storage",
            "backup",
            "--output",
            str(backup_path),
        ]
    )

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        ["--db", str(db_path), "operator", "storage", "restore", "--input", str(backup_path)],
        stdout=stdout,
        stderr=stderr,
    )
    assert status != 0


def test_vinctor_cli_storage_restore_rejects_invalid_input(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    bad_input = tmp_path / "garbage.sqlite"
    _seed_storage_db(db_path)
    bad_input.write_text("not a database", encoding="utf-8")

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        [
            "--db",
            str(db_path),
            "operator",
            "storage",
            "restore",
            "--input",
            str(bad_input),
            "--yes",
        ],
        stdout=stdout,
        stderr=stderr,
    )
    assert status != 0
    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_vinctor_cli_storage_migrate_reports_versions(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    migrate = _run(["--json", "--db", str(db_path), "operator", "storage", "migrate"])

    assert migrate == {
        "db_path": str(db_path),
        "schema_versions": list(range(1, 16)),
    }
    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant is not None


def test_vinctor_cli_keys_list_and_revoke(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    listed = _run([*common, "operator", "keys", "list"])
    assert len(listed["keys"]) == 1
    key_id = listed["keys"][0]["key_id"]
    assert listed["keys"][0]["key_type"] == "workspace"
    assert listed["keys"][0]["status"] == "active"
    serialized = json.dumps(listed)
    assert "key_hash" not in serialized
    assert "raw_key" not in serialized
    assert "wsk_demo" not in serialized

    revoked = _run([*common, "operator", "keys", "revoke", key_id])
    assert revoked["key_id"] == key_id
    assert revoked["status"] == "revoked"

    conn = connect_sqlite(db_path)
    try:
        record = SQLiteLocalKeyRepository(conn).get_by_id(key_id)
    finally:
        conn.close()
    assert record.status == "revoked"


def test_vinctor_cli_grants_revoke_direct_db(tmp_path: Path) -> None:
    # Regression (Codex runtime report 2026-07-11): `grants revoke --db <path>`
    # must revoke against the SQLite DB like every other operator mutation
    # (keys/tokens/require-boundary/bounds), instead of demanding an endpoint +
    # workspace key. The service reads grants per-enforce with no cache, so a
    # direct-DB revoke is consistent and safe.
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    revoked = _run([*common, "operator", "grants", "revoke", "grt_seed"])
    assert revoked["grant_ref"] == "grt_seed"
    assert revoked["status"] == "revoked"
    assert revoked["audit_event_id"].startswith("evt_")

    conn = connect_sqlite(db_path)
    try:
        grant = SQLiteV1Service(conn, initialize_schema=False).grant_repository.get_by_ref(
            "grt_seed"
        )
    finally:
        conn.close()
    assert grant.status == "revoked"


def test_vinctor_cli_grants_revoke_direct_db_unknown_errors(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        ["--db", str(db_path), "--workspace-id", "ws_demo",
         "operator", "grants", "revoke", "grt_missing"],
        stdout=stdout,
        stderr=stderr,
    )
    assert status != 0
    assert "grt_missing" in stderr.getvalue()


def test_vinctor_cli_keys_revoke_unknown_errors(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        [
            "--db",
            str(db_path),
            "--workspace-id",
            "ws_demo",
            "operator",
            "keys",
            "revoke",
            "lkey_nope",
        ],
        stdout=stdout,
        stderr=stderr,
    )
    assert status != 0


def test_vinctor_cli_keys_rotate_workspace_prints_raw_once(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    rotated = _run([*common, "operator", "keys", "rotate", "workspace"])
    assert rotated["raw_key"].startswith("wsk_")
    assert rotated["key_type"] == "workspace"
    assert len(rotated["revoked_key_ids"]) == 1

    # The new key is active; the rotated raw value must not appear in `keys list`.
    listed = _run([*common, "operator", "keys", "list"])
    active = [key for key in listed["keys"] if key["status"] == "active"]
    assert len(active) == 1
    assert active[0]["key_id"] == rotated["key_id"]
    assert rotated["raw_key"] not in json.dumps(listed)
    assert "raw_key" not in json.dumps(listed)


def test_vinctor_cli_keys_rotate_agent(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    rotated = _run([*common, "operator", "keys", "rotate", "agent", "--agent-id", "agent_runner"])
    assert rotated["raw_key"].startswith("aak_")
    assert rotated["key_type"] == "agent"
    assert rotated["agent_id"] == "agent_runner"


def test_vinctor_cli_keys_rotate_auditor(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    rotated = _run([*common, "operator", "keys", "rotate", "auditor"])
    assert rotated["raw_key"].startswith("auk_")
    assert rotated["key_type"] == "auditor"
    assert rotated["agent_id"] is None


def test_vinctor_cli_keys_rotate_service_operator(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    rotated = _run([*common, "operator", "keys", "rotate", "service-operator"])
    assert rotated["raw_key"].startswith("sok_")
    assert rotated["key_type"] == "service_operator"
    assert rotated["workspace_id"] == "*"

    listed = _run([*common, "operator", "keys", "list", "--service"])
    assert listed["keys"][0]["key_id"] == rotated["key_id"]


def test_vinctor_cli_keys_rotate_pep(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    rotated = _run([*common, "operator", "keys", "rotate", "pep", "--pep-id", "pep_runner"])
    assert rotated["raw_key"].startswith("pep_")
    assert rotated["key_type"] == "resource_server"
    assert rotated["agent_id"] == "pep_runner"


def test_vinctor_cli_bounds_set_with_max_ttl_and_show(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    set_result = _run(
        [
            *common,
            "operator",
            "bounds",
            "set",
            "agent_runner",
            "--scope",
            "execute:ci/test",
            "--max-ttl",
            "30m",
        ]
    )
    shown = _run([*common, "operator", "bounds", "show", "agent_runner"])

    assert set_result["scopes"] == ["execute:ci/test"]
    assert set_result["max_ttl_seconds"] == 1800
    assert shown["scopes"] == ["execute:ci/test"]
    assert shown["max_ttl_seconds"] == 1800


def test_vinctor_cli_bounds_set_without_max_ttl(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    set_result = _run(
        [
            *common,
            "operator",
            "bounds",
            "set",
            "agent_runner",
            "--scope",
            "execute:ci/test",
        ]
    )
    shown = _run([*common, "operator", "bounds", "show", "agent_runner"])

    assert set_result["max_ttl_seconds"] is None
    assert shown["max_ttl_seconds"] is None


def test_vinctor_cli_operator_require_boundary_enable_show(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-boundary", "enable", "agent_runner"])
    shown = _run([*common, "operator", "require-boundary", "show", "agent_runner"])
    disabled = _run([*common, "operator", "require-boundary", "disable", "agent_runner"])
    shown_after = _run([*common, "operator", "require-boundary", "show", "agent_runner"])

    assert enabled["require_boundary"] is True
    assert shown["require_boundary"] is True
    assert disabled["require_boundary"] is False
    assert shown_after["require_boundary"] is False


def test_vinctor_cli_require_boundary_workspace_default(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-boundary", "enable", "--workspace"])
    shown = _run([*common, "operator", "require-boundary", "show", "--workspace"])
    assert enabled["require_boundary"] is True and enabled["scope"] == "workspace"
    assert shown["require_boundary"] is True


def test_vinctor_cli_operator_require_subject_token_enable_show(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-subject-token", "enable", "agent_runner"])
    shown = _run([*common, "operator", "require-subject-token", "show", "agent_runner"])
    disabled = _run([*common, "operator", "require-subject-token", "disable", "agent_runner"])
    shown_after = _run([*common, "operator", "require-subject-token", "show", "agent_runner"])

    assert enabled["require_subject_token"] is True
    assert shown["require_subject_token"] is True
    assert disabled["require_subject_token"] is False
    assert shown_after["require_subject_token"] is False


def test_vinctor_cli_require_subject_token_workspace_default(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-subject-token", "enable", "--workspace"])
    shown = _run([*common, "operator", "require-subject-token", "show", "--workspace"])
    assert enabled["require_subject_token"] is True and enabled["scope"] == "workspace"
    assert shown["require_subject_token"] is True


def test_vinctor_cli_operator_require_pop_enable_show(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-pop", "enable", "agent_runner"])
    shown = _run([*common, "operator", "require-pop", "show", "agent_runner"])
    disabled = _run([*common, "operator", "require-pop", "disable", "agent_runner"])
    shown_after = _run([*common, "operator", "require-pop", "show", "agent_runner"])

    assert enabled["require_pop"] is True
    assert shown["require_pop"] is True
    assert disabled["require_pop"] is False
    assert shown_after["require_pop"] is False


def test_vinctor_cli_require_pop_workspace_default(tmp_path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]
    enabled = _run([*common, "operator", "require-pop", "enable", "--workspace"])
    shown = _run([*common, "operator", "require-pop", "show", "--workspace"])
    assert enabled["require_pop"] is True and enabled["scope"] == "workspace"
    assert shown["require_pop"] is True


def test_vinctor_cli_require_pop_enable_warns_about_pop_lockout(tmp_path) -> None:
    # Footgun guard: enabling require-pop DENIES the agent on every enforce
    # unless its client presents PoP-bound tokens. The operator must be warned at
    # enable time. The warning is operator-facing only (it never reaches the agent
    # deny, which stays coarse) and never appears on disable/show.
    db_path = tmp_path / "vinctor.sqlite"
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    enabled = _run([*common, "operator", "require-pop", "enable", "agent_runner"])
    assert enabled["require_pop"] is True
    assert "warning" in enabled
    assert "pop" in str(enabled["warning"]).lower()

    disabled = _run([*common, "operator", "require-pop", "disable", "agent_runner"])
    assert "warning" not in disabled
    shown = _run([*common, "operator", "require-pop", "show", "agent_runner"])
    assert "warning" not in shown


def test_vinctor_cli_tokens_list_revoke_then_delegated_enforce_denies(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    raw, token_id = _mint_subject_token(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    listed = _run([*common, "operator", "tokens", "list"])
    assert len(listed["tokens"]) == 1
    row = listed["tokens"][0]
    assert row["token_id"] == token_id
    assert row["agent_id"] == "agent_runner"
    assert row["grant_ref"] == "grt_seed"
    assert row["audience"] == "pep_runner"
    assert row["revoked"] is False
    serialized = json.dumps(listed)
    assert "token_hash" not in serialized
    assert raw not in serialized

    # Before revocation, the token proves identity on the delegated path.
    assert _delegated_enforce(db_path, raw).decision == "permit"

    revoked = _run([*common, "operator", "tokens", "revoke", token_id])
    assert revoked["token_id"] == token_id
    assert revoked["revoked"] is True

    shown = _run([*common, "operator", "tokens", "list"])
    assert shown["tokens"][0]["revoked"] is True

    # After revocation, the same raw token fails closed (403, not a permit).
    denied = _delegated_enforce(db_path, raw)
    assert denied.status_code == 403
    assert denied.error == "forbidden"
    assert denied.decision is None


def test_vinctor_cli_tokens_list_does_not_leak_pop_secret(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)
    token_id = _insert_pop_token(db_path)
    common = ["--json", "--db", str(db_path), "--workspace-id", "ws_demo"]

    listed = _run([*common, "operator", "tokens", "list"])
    assert len(listed["tokens"]) == 1
    row = listed["tokens"][0]
    assert row["token_id"] == token_id
    assert "pop_secret" not in row
    serialized = json.dumps(listed)
    assert "pop_secret" not in serialized
    assert "pop-secret-value" not in serialized


def test_vinctor_cli_tokens_revoke_unknown_errors(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(
        [
            "--db",
            str(db_path),
            "--workspace-id",
            "ws_demo",
            "operator",
            "tokens",
            "revoke",
            "vtk_nope",
        ],
        stdout=stdout,
        stderr=stderr,
    )
    assert status != 0


def test_vinctor_cli_operator_grants_revoke_then_enforce_denies(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        common = _common_args(handle, json_output=True)
        revoked = _run([*common, "operator", "grants", "revoke", handle.grant_ref])
        assert revoked["grant_ref"] == handle.grant_ref
        assert revoked["status"] == "revoked"
        assert revoked["audit_event_id"]

        # The text summary surfaces the grant_ref + audit_event_id.
        text_common = _common_args(handle, json_output=False)
        summary = _run_text([*text_common, "operator", "grants", "revoke", handle.grant_ref])
        assert handle.grant_ref in summary
        assert "audit_event_id=" in summary

        # A subsequent enforce on the revoked grant is denied with "is revoked".
        stdout, stderr = StringIO(), StringIO()
        status = run_vinctor(
            [
                *common,
                "agent",
                "enforce",
                "--grant-ref",
                handle.grant_ref,
                "--action",
                "execute",
                "--resource",
                "ci/test",
            ],
            stdout=stdout,
            stderr=stderr,
        )
        assert status != 0
        decision = json.loads(stdout.getvalue())
        assert decision["decision"] == "deny"
        # No-disclosure: the deny reason is the coarse code only; it never names
        # the grant.
        assert decision["reason"] == "grant_revoked"
        assert "grnt_" not in stdout.getvalue()
    finally:
        _stop_service(handle)


def test_vinctor_cli_operator_grants_revoke_unknown_errors(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        common = _common_args(handle, json_output=True)
        stdout, stderr = StringIO(), StringIO()
        status = run_vinctor(
            [*common, "operator", "grants", "revoke", "grt_does_not_exist"],
            stdout=stdout,
            stderr=stderr,
        )
        assert status != 0
        assert stdout.getvalue() == ""
        assert "Traceback" not in stderr.getvalue()
        assert "404" in stderr.getvalue()
    finally:
        _stop_service(handle)


def test_vinctor_cli_operator_grants_revoke_requires_workspace_key(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        stdout, stderr = StringIO(), StringIO()
        status = run_vinctor(
            [
                "--endpoint",
                handle.endpoint,
                "operator",
                "grants",
                "revoke",
                handle.grant_ref,
            ],
            stdout=stdout,
            stderr=stderr,
        )
        assert status != 0
        assert "Traceback" not in stderr.getvalue()
        assert "workspace key is required" in stderr.getvalue()
    finally:
        _stop_service(handle)


def _mint_subject_token(db_path: Path) -> tuple[str, str]:
    conn = connect_sqlite(db_path)
    try:
        result = SQLiteV1Service(conn).mint_subject_token(
            workspace_id="ws_demo",
            agent_id="agent_runner",
            grant_ref="grt_seed",
            audience="pep_runner",
            ttl_seconds=300,
            now=NOW,
        )
    finally:
        conn.close()
    assert result.status == "minted"
    return result.token, result.token_id


def _insert_pop_token(db_path: Path) -> str:
    from datetime import timedelta

    from vinctor_service import SubjectToken

    token = SubjectToken(
        token_id="vtk_pop",
        token_hash="hash_pop",
        workspace_id="ws_demo",
        agent_id="agent_runner",
        grant_ref="grt_seed",
        audience="pep_runner",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        created_by="agent_runner",
        pop_secret="pop-secret-value",
    )
    conn = connect_sqlite(db_path)
    try:
        SQLiteV1Service(conn).subject_token_repository.insert(token)
    finally:
        conn.close()
    return token.token_id


def _delegated_enforce(db_path: Path, raw: str):
    conn = connect_sqlite(db_path)
    try:
        return SQLiteV1Service(conn).delegated_enforce(
            V1DelegatedEnforceRequest(
                pep_id="pep_runner",
                workspace_id="ws_demo",
                agent_id="agent_runner",
                grant_ref="grt_seed",
                action="execute",
                resource="ci/test",
                subject_token=raw,
            ),
            now=NOW,
            pep_workspace_id="ws_demo",
        )
    finally:
        conn.close()


def _seed_storage_db(db_path: Path) -> None:
    conn = connect_sqlite(db_path)
    try:
        service = SQLiteV1Service(conn)
        service.set_agent_issuable_scope_bounds(
            workspace_id="ws_demo",
            agent_id="agent_runner",
            scopes=("execute:ci/test",),
            now=NOW,
        )
        service.issue_grant(
            GrantIssueRequest(
                workspace_id="ws_demo",
                target_agent_id="agent_runner",
                requested_scopes=("execute:ci/test",),
                ttl_seconds=3600,
                grant_ref="grt_seed",
            ),
            now=NOW,
        )
        SQLiteLocalKeyRepository(conn).create_workspace_key(
            workspace_id="ws_demo",
            raw_key="wsk_demo",
            now=NOW,
        )
    finally:
        conn.close()


def test_vinctor_cli_output_flag_accepted_after_subcommand(tmp_path: Path) -> None:
    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        # No json_output here: the connection flags only, so we can place the
        # output flag explicitly at the position under test.
        base = [
            "--endpoint",
            handle.endpoint,
            "--agent-key",
            handle.agent_key,
            "--grant-ref",
            handle.grant_ref,
            "--boundary-id",
            handle.boundary.boundary_id,
        ]
        enforce = [
            "agent",
            "enforce",
            "--grant-ref",
            handle.grant_ref,
            "--action",
            "execute",
            "--resource",
            "ci/test",
        ]

        # (a) output flag BEFORE the role (the historical form): JSON is emitted.
        before = _run(["-o", "json", *base, *enforce])
        # (b) output flag AFTER the leaf subcommand (the new form): also JSON,
        # and the decision matches (audit_event_id is a fresh per-call id).
        after = _run([*base, *enforce, "-o", "json"])
        assert before["decision"] == "permit"
        assert after["decision"] == before["decision"]

        # --json after the leaf is also accepted and selects JSON output.
        after_json = _run([*base, *enforce, "--json"])
        assert after_json["decision"] == before["decision"]
    finally:
        _stop_service(handle)


def test_vinctor_cli_connection_flag_accepted_after_subcommand(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    audit = ["operator", "audit", "list"]

    # (a) --db BEFORE the role (the historical form).
    before = _run(["--json", "--db", str(db_path), *audit])
    # (b) --db AFTER the leaf subcommand (the new form).
    after = _run(["--json", *audit, "--db", str(db_path)])
    assert after == before

    # (c) --db in BOTH positions: the leaf (trailing) value wins.
    other_db = tmp_path / "other.sqlite"
    _seed_storage_db(other_db)
    both = _run(["--json", "--db", str(other_db), *audit, "--db", str(db_path)])
    assert both == before


def test_vinctor_cli_audit_list_filters_by_reason(tmp_path) -> None:
    # Completes the require-pop footgun surfacing: an operator can pull a specific
    # rejection class (e.g. every `pop_required` lockout) instead of eyeballing the
    # whole log. Storage already supports reason filtering; this exposes it on the CLI.
    from vinctor_core.audit import build_rejection_audit_event

    db_path = tmp_path / "vinctor.sqlite"
    conn = connect_sqlite(db_path)
    try:
        writer = SQLiteV1Service(conn).audit_writer
        writer.write(
            build_rejection_audit_event(
                reason_code="pop_required", workspace_id="ws_demo", agent_id="agent_a",
                action="write", resource="repo/x", created_at=NOW,
            )
        )
        writer.write(
            build_rejection_audit_event(
                reason_code="agent_grant_mismatch", workspace_id="ws_demo",
                agent_id="agent_a", action="write", resource="repo/y", created_at=NOW,
            )
        )
    finally:
        conn.close()

    common = ["--json", "--db", str(db_path)]
    everything = _run([*common, "operator", "audit", "list"])
    filtered = _run([*common, "operator", "audit", "list", "--reason", "pop_required"])

    assert len(everything["audit_events"]) == 2
    assert len(filtered["audit_events"]) == 1
    assert filtered["audit_events"][0]["reason_code"] == "pop_required"


def test_vinctor_cli_workspace_id_default_survives_after_subcommand_output_flag(
    tmp_path: Path,
) -> None:
    # (d) NEITHER position sets --workspace-id, even though a trailing global
    # flag (-o json) is parsed at the leaf: the root default must survive and
    # must NOT be clobbered to None by the leaf's omitted copy.
    db_path = tmp_path / "vinctor.sqlite"
    _seed_storage_db(db_path)

    listed = _run(["--db", str(db_path), "operator", "tokens", "list", "-o", "json"])
    assert listed["tokens"] == []


def _start_service(tmp_path: Path, *, scopes: tuple[str, ...]):
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "vinctor.sqlite",
            port=0,
            workspace_id="ws_demo",
            agent_id="agent_runner",
            workspace_key="wsk_demo",
            agent_key="aak_demo",
            grant_ref="grt_bootstrap",
            scopes=scopes,
            boundary_name="claude-code-local",
        ),
        now=NOW,
    )
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    handle._test_thread = thread
    return handle


def _seed_rejected_request_audit(db_path: Path) -> None:
    conn = connect_sqlite(db_path)
    try:
        service = SQLiteV1Service(conn)
        SQLiteLocalKeyRepository(conn).create_workspace_key(
            workspace_id="ws_demo",
            raw_key="wsk_demo",
            now=NOW,
        )
        service.create_grant_request(
            GrantRequestCreateRequest(
                workspace_id="ws_demo",
                requester_agent_id="agent_runner",
                requested_scopes=("write:repo/vinctor-core/README.md",),
                requested_ttl_seconds=1800,
                reason="edit core README",
                request_id="grq_demo",
            ),
            now=NOW,
        )
        service.reject_grant_request(
            request_id="grq_demo",
            workspace_id="ws_demo",
            decided_by="workspace:ws_demo",
            decision_reason="not needed",
            now=NOW,
        )
    finally:
        conn.close()


def _stop_service(handle) -> None:
    handle.server.shutdown()
    handle._test_thread.join(timeout=5)
    handle.close()


def _common_args(handle, *, json_output: bool) -> list[str]:
    args = [
        "--endpoint",
        handle.endpoint,
        "--workspace-key",
        handle.workspace_key,
        "--agent-key",
        handle.agent_key,
        "--grant-ref",
        handle.grant_ref,
        "--boundary-id",
        handle.boundary.boundary_id,
        "--db",
        str(handle.db_path),
    ]
    if json_output:
        args.insert(0, "--json")
    return args


def _run(argv: list[str]) -> dict[str, object]:
    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(argv, stdout=stdout, stderr=stderr)
    assert status == 0, stderr.getvalue()
    return json.loads(stdout.getvalue())


def _run_text(argv: list[str]) -> str:
    stdout = StringIO()
    stderr = StringIO()
    status = run_vinctor(argv, stdout=stdout, stderr=stderr)
    assert status == 0, stderr.getvalue()
    return stdout.getvalue()


def test_vinctor_cli_version_prints_version_and_exits_zero(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # `--version` is a top-level action: it must print and exit 0 BEFORE the
    # "role is required" check fires (the subparsers are required=True).
    with pytest.raises(SystemExit) as excinfo:
        run_vinctor(["--version"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    expected = importlib.metadata.version("vinctor-core")
    assert out.strip() == f"vinctor {expected}"
    assert "role is required" not in out


def test_vinctor_cli_malformed_agent_key_is_clean_cli_error(tmp_path: Path) -> None:
    # A credential carrying a control char / embedded newline must yield a clean
    # one-line CliError (no raw http.client `ValueError: Invalid header value`
    # traceback escaping to the caller).
    handle = _start_service(tmp_path, scopes=("execute:ci/test",))
    try:
        stdout = StringIO()
        stderr = StringIO()
        with contextlib.redirect_stderr(stderr):
            status = run_vinctor(
                [
                    "--endpoint",
                    handle.endpoint,
                    "--agent-key",
                    "aak_demo\nX-Injected: 1",
                    "--grant-ref",
                    handle.grant_ref,
                    "--boundary-id",
                    handle.boundary.boundary_id,
                    "agent",
                    "enforce",
                    "--grant-ref",
                    handle.grant_ref,
                    "--action",
                    "execute",
                    "--resource",
                    "ci/test",
                ],
                stdout=stdout,
                stderr=stderr,
            )
        assert status in (EXIT_AUTH, EXIT_USAGE)
        combined = stdout.getvalue() + stderr.getvalue()
        assert "Traceback" not in combined
        assert "error:" in combined
        # exactly one error line, no stack frames
        assert combined.strip().count("\n") == 0
    finally:
        _stop_service(handle)


def test_request_json_maps_invalid_header_value_to_cli_error() -> None:
    # Direct unit guard: a control char in a header value (which http.client
    # rejects with ValueError) becomes a CliError rather than propagating.
    with pytest.raises(CliError):
        _request_json(
            "http://127.0.0.1:8765",
            "POST",
            "/v1/enforce",
            headers={"X-Agent-Key": "bad\nvalue"},
            body={"action": "execute"},
        )


def _help_text(argv: list[str], capsys: pytest.CaptureFixture[str]) -> str:
    # `--help` is an argparse action: it prints to stdout and raises SystemExit(0).
    with pytest.raises(SystemExit) as excinfo:
        run_vinctor([*argv, "--help"])
    assert excinfo.value.code == 0
    return capsys.readouterr().out


def test_vinctor_cli_help_distinguishes_ambiguous_clusters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # Help text only (no behavior change). The CLI surface has several
    # easy-to-confuse sibling commands; each must carry a gloss that tells them
    # apart in `--help`.

    # operator root distinguishes its resources.
    operator = _help_text(["operator"], capsys)
    assert "requests" in operator
    assert "bounds" in operator
    assert "require-boundary" in operator
    # bounds vs require-boundary are different concepts and must be disambiguated.
    assert "bounds" in operator.lower()

    # operator requests: list vs inbox, view vs timeline, approve vs evaluate.
    requests = _help_text(["operator", "requests"], capsys)
    for leaf in ("list", "inbox", "view", "timeline", "approve", "reject", "evaluate"):
        assert leaf in requests
    # inbox is the pending+triage view; list is the full queue.
    assert "pending" in requests.lower()
    assert "triage" in requests.lower() or "recommend" in requests.lower()
    # timeline is the audit-event chain; view is the single request snapshot.
    assert "audit" in requests.lower()
    assert "snapshot" in requests.lower() or "single request" in requests.lower()
    # evaluate runs auto-approval rules; approve is the manual decision.
    assert "auto-approval" in requests.lower() or "auto approval" in requests.lower()
    assert "manual" in requests.lower()

    # The three require-* mandates each describe what they require.
    rb = _help_text(["operator", "require-boundary"], capsys)
    assert "boundary" in rb.lower()
    rst = _help_text(["operator", "require-subject-token"], capsys)
    assert "subject token" in rst.lower()
    rp = _help_text(["operator", "require-pop"], capsys)
    assert "proof-of-possession" in rp.lower() or "proof of possession" in rp.lower()

    # bounds: the issuable-scope ceiling, distinct from the require-* mandates.
    bounds = _help_text(["operator", "bounds"], capsys)
    assert "scope" in bounds.lower()
    assert "ceiling" in bounds.lower() or "maximum" in bounds.lower() or "bound" in bounds.lower()


def test_vinctor_cli_help_demo_block_and_global_flags(
    capsys: pytest.CaptureFixture[str],
) -> None:
    # The demo block must explain each demo leaf so newcomers pick the right one.
    demo = _help_text(["demo"], capsys)
    for leaf in ("check", "block", "service"):
        assert leaf in demo
    # `block` is the user-facing context-dependent allow/deny showcase.
    assert "context" in demo.lower() or "allow" in demo.lower()

    # Global flags expose their VINCTOR_* env var, and --json/-o document the
    # alias + precedence relationship.
    root = _help_text([], capsys)
    assert "VINCTOR_ENDPOINT" in root
    assert "VINCTOR_DB" in root
    # --json is an alias for `-o json`; --json wins when both are given.
    assert "alias for" in root.lower() and "-o json" in root
    assert "precedence" in root.lower() or "wins" in root.lower()


def _grant_ref_present(db_path: Path, grant_ref: str) -> bool:
    """Read a database directly; an unreadable or schemaless file raises.

    Deliberately no except: if this swallowed sqlite3.DatabaseError as "grant
    absent", a corrupt copy would satisfy the WAL drill below for a reason that
    has nothing to do with WAL.
    """
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT 1 FROM grants WHERE grant_ref = ?", (grant_ref,)
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def test_dr_drill_restored_database_has_a_verifiable_audit_chain(tmp_path: Path) -> None:
    # The runbook's real promise is not "the rows come back" — it is "you still
    # have an audit trail you can stand behind". The existing roundtrip checks a
    # grant survives; nothing checked the chain still verifies, which is the only
    # property that makes the restored log evidence rather than just data.
    db_path = tmp_path / "vinctor.sqlite"
    backup_path = tmp_path / "vinctor.backup.sqlite"
    _seed_storage_db(db_path)
    common = ["--json", "--db", str(db_path)]
    # No --workspace-id: verify walks the whole audit_events chain; the flag is
    # accepted globally but ignored by this subcommand.
    verify = ["operator", "audit", "verify"]

    before = _run([*common, *verify])
    _run([*common, "operator", "storage", "backup", "--output", str(backup_path)])
    _run([*common, "operator", "storage", "reset", "--yes"])
    _run([*common, "operator", "storage", "restore", "--input", str(backup_path), "--yes"])
    after = _run([*common, *verify])

    assert before["ok"] is True
    # Vacuity guard: if the seed ever stops writing audit events, the equality
    # checks below would compare two empty chains and pass.
    assert before["count"] > 0
    assert after["ok"] is True
    # ok=True alone is a weak assertion: an empty chain verifies too. Pin that the
    # restored chain is *the backed-up chain*, head hash and all.
    assert after["head_hash"] == before["head_hash"]
    assert after["head_seq"] == before["head_seq"]
    assert after["count"] == before["count"]


def test_dr_drill_backup_captures_wal_resident_writes(tmp_path: Path) -> None:
    # Why the runbook says `storage backup` and not `cp`. Databases normally run
    # in WAL mode (enabled on every open), so committed rows can sit in the -wal
    # sidecar while the main file looks untouched. The command reads through the
    # SQLite backup API and captures them; copying the main file does not. This
    # is the assumption the whole DR path rests on, so it gets a test rather
    # than a sentence.
    db_path = tmp_path / "vinctor.sqlite"
    backup_path = tmp_path / "vinctor.backup.sqlite"
    naive_copy = tmp_path / "what-an-operator-would-copy.sqlite"

    # Seeds grt_seed; closing the last connection checkpoints it into the main
    # file, so it is the baseline row a naive copy MUST contain.
    _seed_storage_db(db_path)
    conn = connect_sqlite(db_path)
    try:
        # Keep the drill independent of SQLite's default checkpoint threshold:
        # this connection must never checkpoint on its own.
        conn.execute("PRAGMA wal_autocheckpoint = 0")
        service = SQLiteV1Service(conn, initialize_schema=False)
        service.issue_grant(
            GrantIssueRequest(
                workspace_id="ws_demo",
                target_agent_id="agent_runner",
                requested_scopes=("execute:ci/test",),
                ttl_seconds=3600,
                grant_ref="grt_wal_resident",
            ),
            now=NOW,
        )
        # Committed, but still living in the sidecar: nothing has checkpointed.
        assert Path(f"{db_path}-wal").stat().st_size > 0

        # Naive copy first, then the real backup, so both mechanisms are
        # compared against the same source state.
        shutil.copyfile(db_path, naive_copy)
        _run(["--json", "--db", str(db_path), "operator", "storage", "backup",
              "--output", str(backup_path)])
    finally:
        conn.close()

    assert _grant_ref_present(backup_path, "grt_wal_resident") is True
    # The naive copy must be readable and hold the pre-WAL baseline row —
    # otherwise "WAL grant absent" below could just mean "copy unreadable",
    # which would prove nothing about WAL.
    assert _grant_ref_present(naive_copy, "grt_seed") is True
    assert _grant_ref_present(naive_copy, "grt_wal_resident") is False
