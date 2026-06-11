from __future__ import annotations

import json
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from threading import Thread

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

        assert created["routing_hint"] == "manual_review_required"
        assert created["routing_reason"] == "no_matching_rule"
        assert evaluated["status"] == "pending"
        assert evaluated["auto_approval"]["reason"] == "no_matching_rule"
        assert approved["status"] == "approved"
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
