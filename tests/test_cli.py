from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from threading import Thread

import yaml

from vinctor_service import SQLiteV1Service
from vinctor_service.cli import run_vinctor
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service

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


def test_vinctor_demo_check_runs_smoke_flow() -> None:
    result = _run(["--json", "demo", "check"])

    assert result["ok"] is True
    assert result["decision"] == "permit"
    assert result["audit_event_count"] == 5


def test_vinctor_demo_service_runs_user_facing_flow() -> None:
    result = _run(["--json", "demo", "service"])

    assert result["ok"] is True
    assert result["ci_decision"] == "permit"
    assert result["deploy_auto_approval_reason"] == "scope_outside_rule"
    assert result["deploy_decision"] == "permit"
    assert result["repo_core_decision"] == "permit"
    assert result["sibling_repo_status"] == 403
    assert result["sibling_repo_decision"] == "deny"


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


def test_vinctor_cli_policy_apply_export_and_storage_info(tmp_path: Path) -> None:
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
    storage = _run([*common, "operator", "storage", "info"])
    exported = _run([*common, "operator", "policy", "export", "--file", str(exported_path)])

    conn = sqlite3.connect(db_path)
    service = SQLiteV1Service(conn)
    bounds = service.scope_bounds_repository.get_bounds(
        workspace_id="ws_demo",
        agent_id="agent_runner",
    )
    rules = service.list_auto_approval_rules(workspace_id="ws_demo")
    exported_yaml = yaml.safe_load(exported_path.read_text(encoding="utf-8"))

    assert applied == {
        "bounds_set": 1,
        "rules_created": 1,
        "rules_updated": 0,
        "workspace_id": "ws_demo",
    }
    assert storage["schema_versions"] == [1, 2]
    assert exported["agent_bounds"] == 1
    assert exported["auto_approval_rules"] == 1
    assert bounds == ("execute:ci/test", "write:repo/vinctor-core/*")
    assert rules[0].rule_id == "apr_ci"
    assert rules[0].max_ttl_seconds == 1800
    assert exported_yaml["auto_approval_rules"][0]["rule_id"] == "apr_ci"
    conn.close()


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
