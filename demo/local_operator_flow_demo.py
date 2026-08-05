from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from threading import Thread

from vinctor_service.local_admin import run_local_admin
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "vinctor.sqlite"
        handle = prepare_local_service(
            LocalLaunchConfig(
                db_path=db_path,
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_runner",
                workspace_key="wsk_demo",
                agent_key="aak_demo",
                grant_ref="grt_bootstrap",
                scopes=("execute:ci/test",),
                boundary_name="claude-code-local",
            ),
            now=now,
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
            db_args = ["--db", str(db_path)]

            rule_output = _run_admin(
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
                    "1800",
                ]
            )
            request_output = _run_admin(
                [
                    *base_args,
                    "grant-requests",
                    "create",
                    "--scope",
                    "execute:ci/test",
                    "--ttl-seconds",
                    "900",
                    "--reason",
                    "run CI validation for the current task",
                ]
            )
            request_id = request_output.split()[2]
            queue_output = _run_admin([*base_args, "grant-requests", "list"])
            auto_output = _run_admin(
                [*base_args, "grant-requests", "auto-approve", request_id]
            )
            grant_ref = _token_value(auto_output, "grant_ref")
            enforce_output = _run_admin(
                [
                    *base_args,
                    "enforce",
                    "--grant-ref",
                    grant_ref,
                    "--action",
                    "execute",
                    "--resource",
                    "ci/test",
                    "--boundary-id",
                    handle.boundary.boundary_id if handle.boundary is not None else "",
                ]
            )
            audit_output = _run_admin([*db_args, "audit", "--limit", "10"])

            assert "created auto_approval_rule" in rule_output
            assert f"{request_id} status=pending" in queue_output
            assert f"auto-approved grant_request {request_id}" in auto_output
            assert enforce_output.startswith("permit action=execute resource=ci/test")
            assert "grant_request_auto_approved" in audit_output
            assert "action_permitted" in audit_output
        finally:
            handle.server.shutdown()
            thread.join(timeout=5)
            handle.close()

    print("ALL LOCAL OPERATOR FLOW STEPS PASSED")


def _run_admin(argv: list[str]) -> str:
    stdout = StringIO()
    stderr = StringIO()
    status = run_local_admin(argv, stdout=stdout, stderr=stderr)
    if status != 0:
        raise AssertionError(stderr.getvalue())
    return stdout.getvalue().strip()


def _token_value(output: str, key: str) -> str:
    prefix = f"{key}="
    for token in output.split():
        if token.startswith(prefix):
            return token.removeprefix(prefix)
    raise AssertionError(f"missing {key} in output: {output}")


if __name__ == "__main__":
    main()
