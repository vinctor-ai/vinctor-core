from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Thread
from typing import Any

from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import ServiceRuntimeHandle, prepare_service_runtime

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def main() -> None:
    with TemporaryDirectory() as temp_dir:
        db_path = Path(temp_dir) / "vinctor.sqlite"
        bootstrap = prepare_local_service(
            LocalLaunchConfig(
                db_path=db_path,
                port=0,
                workspace_id="ws_demo",
                agent_id="agent_runner",
                workspace_key="wsk_demo",
                agent_key="aak_demo",
                grant_ref="grt_demo",
                scopes=("execute:ci/test",),
                boundary_name="codex-local",
            ),
            now=NOW,
        )
        boundary_id = bootstrap.boundary.boundary_id if bootstrap.boundary else None
        bootstrap.close()

        runtime = prepare_service_runtime(
            ServiceRuntimeConfig(
                host="127.0.0.1",
                port=0,
                sqlite_db_path=db_path,
                service_mode="self_hosted",
            ),
            clock=lambda: NOW,
        )
        try:
            with running_runtime(runtime):
                health_status, health = request_json(runtime, "GET", "/healthz")
                assert health_status == 200
                assert health == {
                    "status": "ok",
                    "service": "vinctor-service",
                    "mode": "self_hosted",
                }

                permit_status, permit = request_json(
                    runtime,
                    "POST",
                    "/v1/enforce",
                    headers={
                        "X-Agent-Key": "aak_demo",
                        "X-Vinctor-Boundary-Id": boundary_id or "",
                    },
                    body={
                        "grant_ref": "grt_demo",
                        "action": "execute",
                        "resource": "ci/test",
                    },
                )
                assert permit_status == 200
                assert permit["decision"] == "permit"

                deny_status, deny = request_json(
                    runtime,
                    "POST",
                    "/v1/enforce",
                    headers={
                        "X-Agent-Key": "aak_demo",
                        "X-Vinctor-Boundary-Id": boundary_id or "",
                    },
                    body={
                        "grant_ref": "grt_demo",
                        "action": "deploy",
                        "resource": "npm/package",
                    },
                )
                assert deny_status == 403
                assert deny["decision"] == "deny"
        finally:
            runtime.close()

    print("ALL SELF-HOSTABLE SERVICE STEPS PASSED ✓")


@contextmanager
def running_runtime(handle: ServiceRuntimeHandle):
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        yield handle
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)


def request_json(
    handle: ServiceRuntimeHandle,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: object | None = None,
) -> tuple[int, dict[str, Any]]:
    host, port = handle.server.server_address
    conn = HTTPConnection(host, port, timeout=5)
    request_headers = {"Content-Type": "application/json", **(headers or {})}
    conn.request(
        method,
        path,
        body=None if body is None else json.dumps(body),
        headers=request_headers,
    )
    response = conn.getresponse()
    parsed = json.loads(response.read().decode("utf-8"))
    conn.close()
    return response.status, parsed


if __name__ == "__main__":
    main()
