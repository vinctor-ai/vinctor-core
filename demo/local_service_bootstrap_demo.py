from __future__ import annotations

import json
import sqlite3
import tempfile
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread

from vinctor_service.keys import AGENT_KEY_PREFIX, WORKSPACE_KEY_PREFIX
from vinctor_service.local_launcher import (
    LocalLaunchConfig,
    prepare_local_service,
    render_env_exports,
)


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "vinctor.sqlite"

        first = prepare_local_service(
            LocalLaunchConfig(
                db_path=db_path,
                port=0,
                boundary_name="claude-code-local",
            ),
            now=now,
        )
        try:
            assert first.agent_key.startswith(AGENT_KEY_PREFIX)
            assert first.workspace_key.startswith(WORKSPACE_KEY_PREFIX)
            assert first.grant_ref.startswith("grt_")
            first_exports = render_env_exports(first)
            assert f'export VINCTOR_ENDPOINT="{first.endpoint}"' in first_exports
            assert f'export VINCTOR_AGENT_KEY="{first.agent_key}"' in first_exports
            assert f'export VINCTOR_GRANT_REF="{first.grant_ref}"' in first_exports
            assert f'export VINCTOR_WORKSPACE_KEY="{first.workspace_key}"' in first_exports
            assert 'export VINCTOR_BOUNDARY_ID="' in first_exports
        finally:
            first.close()

        second = prepare_local_service(
            LocalLaunchConfig(
                db_path=db_path,
                port=0,
                workspace_key=first.workspace_key,
                agent_key=first.agent_key,
                grant_ref=first.grant_ref,
                boundary_name="claude-code-local",
            ),
            now=now,
        )
        thread = Thread(target=second.server.serve_forever, daemon=True)
        thread.start()
        try:
            assert second.boundary is not None
            assert count_local_keys(db_path) == 2
            assert count_raw_key_matches(db_path, first.workspace_key, first.agent_key) == 0

            status, response = post_enforce(
                endpoint=second.endpoint,
                agent_key=second.agent_key,
                grant_ref=second.grant_ref,
                boundary_id=second.boundary.boundary_id,
            )

            assert status == 200
            assert response["decision"] == "permit"
            assert second.service.audit_events[-1].reason == "permitted"
            assert second.service.audit_events[-1].boundary_id == second.boundary.boundary_id
        finally:
            second.server.shutdown()
            thread.join(timeout=5)
            second.close()

    print("ALL LOCAL SERVICE BOOTSTRAP STEPS PASSED \u2713")


def count_local_keys(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute("SELECT COUNT(*) FROM local_keys").fetchone()[0]
    finally:
        conn.close()


def count_raw_key_matches(
    db_path: Path,
    workspace_key: str,
    agent_key: str,
) -> int:
    conn = sqlite3.connect(db_path)
    try:
        return conn.execute(
            """
            SELECT COUNT(*)
            FROM local_keys
            WHERE key_hash IN (?, ?)
            """,
            (workspace_key, agent_key),
        ).fetchone()[0]
    finally:
        conn.close()


def post_enforce(
    *,
    endpoint: str,
    agent_key: str,
    grant_ref: str,
    boundary_id: str | None,
) -> tuple[int, dict[str, object]]:
    host, port_text = endpoint.removeprefix("http://").split(":")
    conn = HTTPConnection(host, int(port_text), timeout=5)
    headers = {
        "Content-Type": "application/json",
        "X-Agent-Key": agent_key,
    }
    if boundary_id is not None:
        headers["X-Vinctor-Boundary-Id"] = boundary_id

    conn.request(
        "POST",
        "/v1/enforce",
        body=json.dumps(
            {
                "grant_ref": grant_ref,
                "action": "write",
                "resource": "repo/feature/readme",
            }
        ),
        headers=headers,
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


if __name__ == "__main__":
    main()
