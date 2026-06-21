from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from threading import Thread

import yaml

from vinctor_service import GrantRequestCreateRequest, SQLiteV1Service
from vinctor_service.cli import run_vinctor
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.models import GrantIssueRequest

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
    assert "valid workspace key is required" in stderr.getvalue()
    assert stdout.getvalue() == ""


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
    assert service_info["schema_versions"] == [1, 2, 3]
    assert service_info["schema_version"] == 3
    assert exported["agent_bounds"] == 1
    assert exported["auto_approval_rules"] == 1
    assert bounds == ("execute:ci/test", "write:repo/vinctor-core/*")
    assert rules[0].rule_id == "apr_ci"
    assert rules[0].max_ttl_seconds == 1800
    assert exported_yaml["auto_approval_rules"][0]["rule_id"] == "apr_ci"
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
    conn = sqlite3.connect(db_path)
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
    assert backup["schema_versions"] == [1, 2, 3]
    assert reset == {
        "db_path": str(db_path),
        "reset": True,
        "schema_versions": [1, 2, 3],
    }

    backup_conn = sqlite3.connect(backup_path)
    reset_conn = sqlite3.connect(db_path)
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
    conn = sqlite3.connect(db_path)
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
    assert info["schema_version"] == 3
    assert info["schema_versions"] == [1, 2, 3]
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
        "schema_versions": [1, 2, 3],
    }
    conn = sqlite3.connect(db_path)
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
    conn = sqlite3.connect(db_path)
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

    assert migrate == {"db_path": str(db_path), "schema_versions": [1, 2, 3]}
    conn = sqlite3.connect(db_path)
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

    conn = sqlite3.connect(db_path)
    try:
        record = SQLiteLocalKeyRepository(conn).get_by_id(key_id)
    finally:
        conn.close()
    assert record.status == "revoked"


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


def _seed_storage_db(db_path: Path) -> None:
    conn = sqlite3.connect(db_path)
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
    conn = sqlite3.connect(db_path)
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
