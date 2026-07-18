from __future__ import annotations

from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from threading import Thread

from vinctor_service import GrantRequestCreateRequest, SQLiteV1Service
from vinctor_service.local_admin import run_local_admin
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.sqlite_txn import connect_sqlite

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
WORKSPACE_KEY = f"wsk_{'w' * 32}"
AGENT_KEY = f"aak_{'a' * 32}"


def test_local_admin_drives_request_rule_auto_approve_and_enforce(
    tmp_path: Path,
) -> None:
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "vinctor.sqlite",
            port=0,
            workspace_id="ws_demo",
            agent_id="agent_runner",
            workspace_key=WORKSPACE_KEY,
            agent_key=AGENT_KEY,
            grant_ref="grt_bootstrap",
            scopes=("execute:ci/test",),
        ),
        now=NOW,
    )
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        base_args = [
            "--endpoint",
            handle.endpoint,
            "--workspace-key",
            handle.workspace_key,
            "--agent-key",
            handle.agent_key,
        ]

        rule_out = _run(
            [
                *base_args,
                "auto-approval-rules",
                "create",
                "--name",
                "CI auto approval",
                "--target-agent-id",
                "agent_runner",
                "--scope",
                "execute:ci/test",
                "--max-ttl-seconds",
                "3600",
            ]
        )
        request_out = _run(
            [
                *base_args,
                "grant-requests",
                "create",
                "--scope",
                "execute:ci/test",
                "--ttl-seconds",
                "1800",
                "--reason",
                "run CI validation",
            ]
        )
        request_id = request_out.split()[2]
        list_out = _run([*base_args, "grant-requests", "list"])
        auto_out = _run([*base_args, "grant-requests", "auto-approve", request_id])
        grant_ref = _token_value(auto_out, "grant_ref")
        enforce_out = _run(
            [
                *base_args,
                "enforce",
                "--grant-ref",
                grant_ref,
                "--action",
                "execute",
                "--resource",
                "ci/test",
            ]
        )

        assert "created auto_approval_rule" in rule_out
        assert "created grant_request" in request_out
        assert request_id in list_out
        assert f"auto-approved grant_request {request_id}" in auto_out
        assert enforce_out.startswith("permit action=execute resource=ci/test")
        assert [event.event_type for event in handle.service.audit_events
                if event.event_class == "decision"] == [
            "grant_issued",
            "grant_requested",
            "grant_issued",
            "grant_request_auto_approved",
            "action_permitted",
        ]
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()


def test_local_admin_bounds_and_audit_use_local_db(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"

    bounds_out = _run(
        [
            "--db",
            str(db_path),
            "--workspace-id",
            "ws_demo",
            "--agent-id",
            "agent_runner",
            "bounds",
            "set",
            "--scope",
            "execute:ci/test",
        ]
    )
    show_out = _run(
        [
            "--db",
            str(db_path),
            "--workspace-id",
            "ws_demo",
            "--agent-id",
            "agent_runner",
            "bounds",
            "show",
        ]
    )

    conn = connect_sqlite(db_path)
    try:
        service = SQLiteV1Service(conn)
        service.create_grant_request(
            GrantRequestCreateRequest(
                workspace_id="ws_demo",
                requester_agent_id="agent_runner",
                requested_scopes=("execute:ci/test",),
                requested_ttl_seconds=1800,
                reason="run CI validation",
                request_id="grq_demo",
            ),
            now=NOW,
        )
    finally:
        conn.close()

    audit_out = _run(["--db", str(db_path), "audit", "--limit", "5"])

    assert "set bounds workspace=ws_demo agent=agent_runner scopes=execute:ci/test" in bounds_out
    assert "bounds workspace=ws_demo agent=agent_runner scopes=execute:ci/test" in show_out
    assert "grant_requested" in audit_out
    assert "agent_runner" in audit_out


def test_local_admin_reports_missing_endpoint() -> None:
    stdout = StringIO()
    stderr = StringIO()

    status = run_local_admin(
        ["--workspace-key", "wsk_demo", "grant-requests", "list"],
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 2
    assert "endpoint is required" in stderr.getvalue()


def _run(argv: list[str]) -> str:
    stdout = StringIO()
    stderr = StringIO()
    status = run_local_admin(argv, stdout=stdout, stderr=stderr)
    assert status == 0, stderr.getvalue()
    return stdout.getvalue().strip()


def _token_value(output: str, key: str) -> str:
    prefix = f"{key}="
    for token in output.split():
        if token.startswith(prefix):
            return token.removeprefix(prefix)
    raise AssertionError(f"missing {key} in output: {output}")
