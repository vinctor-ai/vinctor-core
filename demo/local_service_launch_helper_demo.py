from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread

from vinctor_service.local_launcher import (
    LocalLaunchConfig,
    prepare_local_service,
    render_env_exports,
)

WORKSPACE_KEY = f"wsk_{'w' * 32}"
AGENT_KEY = f"aak_{'a' * 32}"


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    with tempfile.TemporaryDirectory() as temp_dir:
        handle = prepare_local_service(
            LocalLaunchConfig(
                db_path=Path(temp_dir) / "vinctor.sqlite",
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_release",
                workspace_key=WORKSPACE_KEY,
                agent_key=AGENT_KEY,
                grant_ref="grt_demo",
                scopes=("write:repo/feature/*",),
                boundary_name="claude-code-local",
            ),
            now=now,
        )
        thread = Thread(target=handle.server.serve_forever, daemon=True)
        thread.start()
        try:
            exports = render_env_exports(handle)
            assert 'export VINCTOR_ENDPOINT="' in exports
            assert f'export VINCTOR_AGENT_KEY="{AGENT_KEY}"' in exports
            assert 'export VINCTOR_GRANT_REF="grt_demo"' in exports
            assert f'export VINCTOR_WORKSPACE_KEY="{WORKSPACE_KEY}"' in exports
            assert 'export VINCTOR_BOUNDARY_ID="' in exports

            # This mirrors the HTTP shape a local runtime hook can send after
            # reading VINCTOR_ENDPOINT, VINCTOR_AGENT_KEY, VINCTOR_GRANT_REF,
            # and optional VINCTOR_BOUNDARY_ID from the printed exports.
            status, response = post_enforce(
                endpoint=handle.endpoint,
                agent_key=handle.agent_key,
                grant_ref=handle.grant_ref,
                boundary_id=handle.boundary.boundary_id if handle.boundary else None,
            )
            assert status == 200
            assert response["decision"] == "permit"

            audit_events = handle.service.audit_events
            # Control and decision events share one chain (ADR 0019). Select the
            # decision by the id returned to the caller instead of assuming a
            # fixed number of bootstrap control events.
            assert [event.event_type for event in audit_events].count("grant_issued") == 1
            decision_events = [
                event
                for event in audit_events
                if event.event_id == response["audit_event_id"]
            ]
            assert len(decision_events) == 1
            assert decision_events[0].event_type == "action_permitted"
            assert decision_events[0].boundary_id == handle.boundary.boundary_id
            assert decision_events[0].runtime == "claude-code"
            assert decision_events[0].boundary_type == "pretooluse"
        finally:
            handle.server.shutdown()
            thread.join(timeout=5)
            handle.close()

    print("ALL LOCAL SERVICE LAUNCH HELPER STEPS PASSED \u2713")


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
