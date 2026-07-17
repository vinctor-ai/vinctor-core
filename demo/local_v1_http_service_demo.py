from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

from vinctor_core import BoundaryRegistrationInput, Grant
from vinctor_service import (
    AgentIdentity,
    SQLiteV1Service,
    create_v1_http_server,
)
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.sqlite_pool import SQLiteServicePool
from vinctor_service.sqlite_txn import connect_sqlite


def main() -> None:
    now = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "vinctor.sqlite"
        conn = connect_sqlite(db_path, check_same_thread=False)
        pool: SQLiteServicePool | None = None
        try:
            service = SQLiteV1Service(conn)
            service.insert_grant(
                Grant(
                    grant_id="grnt_demo",
                    grant_ref="grt_demo",
                    workspace_id="ws_demo",
                    agent_id="agent_release",
                    scopes=("write:repo/feature/*",),
                    status="active",
                    expires_at=now + timedelta(hours=1),
                )
            )
            boundary = service.register_boundary(
                BoundaryRegistrationInput(
                    workspace_id="ws_demo",
                    name="claude-code-local",
                    runtime="claude-code",
                    boundary_type="pretooluse",
                ),
                now=now,
                boundary_id="bnd_demo",
            )
            pool = SQLiteServicePool(
                db_path,
                primary_connection=conn,
                primary_service=service,
                primary_key_repository=SQLiteLocalKeyRepository(conn),
            )

            server = create_v1_http_server(
                ("127.0.0.1", 0),
                service=pool.service,
                agent_identities={
                    "agent_key_demo": AgentIdentity(
                        workspace_id="ws_demo",
                        agent_id="agent_release",
                    )
                },
                clock=lambda: now,
                request_scope=pool.request_scope,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                permit_status, permit = post_json(
                    server,
                    payload={
                        "grant_ref": "grt_demo",
                        "action": "write",
                        "resource": "repo/feature/readme",
                    },
                    headers={"X-Vinctor-Boundary-Id": boundary.boundary_id},
                )
                assert permit_status == 200
                assert permit["decision"] == "permit"

                deny_status, deny = post_json(
                    server,
                    payload={
                        "grant_ref": "grt_demo",
                        "action": "send",
                        "resource": "email/external",
                    },
                )
                assert deny_status == 403
                assert deny["decision"] == "deny"
                assert deny["error"] == "action_denied"

                missing_status, missing = post_json(
                    server,
                    payload={
                        "grant_ref": "grt_missing",
                        "action": "write",
                        "resource": "repo/feature/readme",
                    },
                )
                assert missing_status == 403  # existence oracle: generic 403
                assert missing["error"] == "forbidden"  # existence oracle: generic 403

                strict_status, strict = post_json(
                    server,
                    payload={
                        "grant_ref": "grt_demo",
                        "action": "write",
                        "resource": "repo/feature/readme",
                        "boundary_id": "bnd_body_not_allowed",
                    },
                )
                assert strict_status == 400
                assert strict["error"] == "invalid_request"

                audit_events = service.audit_events
                # Timing oracle closed: the unknown grant records a coarse
                # rejection too, so audit is [permit, deny, unknown-rejection].
                assert len(audit_events) == 3
                assert audit_events[0].event_id == permit["audit_event_id"]
                assert audit_events[0].boundary_id == "bnd_demo"
                assert audit_events[0].runtime == "claude-code"
                assert audit_events[0].boundary_type == "pretooluse"
                assert audit_events[1].event_id == deny["audit_event_id"]
                assert audit_events[1].decision == "deny"
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()
        finally:
            if pool is not None:
                pool.close()
            else:
                conn.close()

    print("ALL LOCAL V1 HTTP SERVICE STEPS PASSED \u2713")


def post_json(
    server: ThreadingHTTPServer,
    *,
    payload: dict[str, str],
    headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    request_headers = {
        "Content-Type": "application/json",
        "X-Agent-Key": "agent_key_demo",
        **(headers or {}),
    }
    conn.request(
        "POST",
        "/v1/enforce",
        body=json.dumps(payload),
        headers=request_headers,
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


if __name__ == "__main__":
    main()
