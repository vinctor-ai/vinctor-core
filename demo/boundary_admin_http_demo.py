from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

from vinctor_core import Grant
from vinctor_service import (
    AgentIdentity,
    SQLiteV1Service,
    WorkspaceIdentity,
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
                workspace_identities={
                    "workspace_key_demo": WorkspaceIdentity(workspace_id="ws_demo"),
                    "workspace_key_other": WorkspaceIdentity(workspace_id="ws_other"),
                },
                clock=lambda: now,
                request_scope=pool.request_scope,
            )
            thread = Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                create_status, created = post_json(
                    server,
                    path="/v1/boundaries",
                    payload={
                        "name": "claude-code-local",
                        "runtime": "claude-code",
                        "boundary_type": "pretooluse",
                        "mode": "fail_closed",
                    },
                    headers={"X-Workspace-Key": "workspace_key_demo"},
                )
                assert create_status == 201
                assert created["boundary_id"].startswith("bnd_")

                list_status, listed = get_json(
                    server,
                    path="/v1/boundaries",
                    headers={"X-Workspace-Key": "workspace_key_demo"},
                )
                assert list_status == 200
                assert listed == {"boundaries": [created]}

                get_status, loaded = get_json(
                    server,
                    path=f"/v1/boundaries/{created['boundary_id']}",
                    headers={"X-Workspace-Key": "workspace_key_demo"},
                )
                assert get_status == 200
                assert loaded == created

                other_status, other = get_json(
                    server,
                    path=f"/v1/boundaries/{created['boundary_id']}",
                    headers={"X-Workspace-Key": "workspace_key_other"},
                )
                assert other_status == 404
                # Operator boundary-registry lookup (workspace key), not the agent
                # enforce path — it keeps the precise reason.
                assert other["error"] == "boundary_not_found"

                disable_status, disabled = post_json(
                    server,
                    path=f"/v1/boundaries/{created['boundary_id']}/disable",
                    payload=None,
                    headers={"X-Workspace-Key": "workspace_key_demo"},
                )
                assert disable_status == 200
                assert disabled["status"] == "disabled"

                disabled_enforce_status, disabled_enforce = post_json(
                    server,
                    path="/v1/enforce",
                    payload={
                        "grant_ref": "grt_demo",
                        "action": "write",
                        "resource": "repo/feature/readme",
                    },
                    headers={
                        "X-Agent-Key": "agent_key_demo",
                        "X-Vinctor-Boundary-Id": created["boundary_id"],
                    },
                )
                assert disabled_enforce_status == 403
                assert disabled_enforce["error"] == "boundary_unavailable"

                enable_status, enabled = post_json(
                    server,
                    path=f"/v1/boundaries/{created['boundary_id']}/enable",
                    payload=None,
                    headers={"X-Workspace-Key": "workspace_key_demo"},
                )
                assert enable_status == 200
                assert enabled["status"] == "active"

                permit_status, permit = post_json(
                    server,
                    path="/v1/enforce",
                    payload={
                        "grant_ref": "grt_demo",
                        "action": "write",
                        "resource": "repo/feature/readme",
                    },
                    headers={
                        "X-Agent-Key": "agent_key_demo",
                        "X-Vinctor-Boundary-Id": created["boundary_id"],
                    },
                )
                assert permit_status == 200
                assert permit["decision"] == "permit"

                audit_events = service.list_filtered(
                    "ws_demo", event_class="decision"
                )
                assert len(audit_events) == 2
                assert audit_events[0].boundary_id == created["boundary_id"]
                assert audit_events[0].runtime == "claude-code"
                assert audit_events[0].boundary_type == "pretooluse"
                assert audit_events[0].reason == "boundary_inactive"
                assert audit_events[1].boundary_id == created["boundary_id"]
                assert audit_events[1].runtime == "claude-code"
                assert audit_events[1].boundary_type == "pretooluse"
                assert audit_events[1].decision == "permit"
            finally:
                server.shutdown()
                thread.join(timeout=5)
                server.server_close()
        finally:
            if pool is not None:
                pool.close()
            else:
                conn.close()

    print("ALL BOUNDARY ADMIN HTTP STEPS PASSED \u2713")


def post_json(
    server: ThreadingHTTPServer,
    *,
    path: str,
    payload: dict[str, str] | None,
    headers: dict[str, str],
) -> tuple[int, dict[str, Any]]:
    return request_json(server, method="POST", path=path, payload=payload, headers=headers)


def get_json(
    server: ThreadingHTTPServer,
    *,
    path: str,
    headers: dict[str, str],
) -> tuple[int, dict[str, Any]]:
    return request_json(server, method="GET", path=path, payload=None, headers=headers)


def request_json(
    server: ThreadingHTTPServer,
    *,
    method: str,
    path: str,
    payload: dict[str, str] | None,
    headers: dict[str, str],
) -> tuple[int, dict[str, Any]]:
    host, port = server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    request_headers = {"Content-Type": "application/json", **headers}
    conn.request(
        method,
        path,
        body=json.dumps(payload) if payload is not None else None,
        headers=request_headers,
    )
    response = conn.getresponse()
    response_body = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, response_body


if __name__ == "__main__":
    main()
