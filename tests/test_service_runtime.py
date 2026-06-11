from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from typing import Any

from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import (
    ServiceRuntimeHandle,
    prepare_service_runtime,
    render_service_runtime_banner,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


@contextmanager
def running_runtime(handle: ServiceRuntimeHandle):
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        yield handle
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)


def test_service_runtime_serves_health_without_secret_leakage(tmp_path: Path) -> None:
    config = ServiceRuntimeConfig(
        sqlite_db_path=tmp_path / "vinctor.sqlite",
        port=0,
        service_mode="self_hosted",
    )
    handle = prepare_service_runtime(config, clock=lambda: NOW)
    try:
        with running_runtime(handle):
            status, body, raw = request_json(handle, "GET", "/healthz")

        assert status == 200
        assert body == {
            "status": "ok",
            "service": "vinctor-service",
            "mode": "self_hosted",
        }
        assert "vinctor.sqlite" not in raw
        assert "aak_" not in raw
        assert "wsk_" not in raw
        assert "grt_" not in raw
    finally:
        handle.close()


def test_service_runtime_rejects_non_get_health_method(tmp_path: Path) -> None:
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(sqlite_db_path=tmp_path / "vinctor.sqlite", port=0),
        clock=lambda: NOW,
    )
    try:
        with running_runtime(handle):
            status, body, _ = request_json(handle, "POST", "/healthz", body={})

        assert status == 405
        assert body["error"] == "method_not_allowed"
    finally:
        handle.close()


def test_service_runtime_preserves_existing_enforce_routes(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    bootstrap = prepare_local_service(
        LocalLaunchConfig(
            db_path=db_path,
            port=0,
            workspace_id="ws_demo",
            agent_id="agent_runner",
            workspace_key="wsk_demo",
            agent_key="aak_demo",
            grant_ref="grt_demo",
            scopes=("write:repo/feature/*",),
            boundary_name="codex-local",
        ),
        now=NOW,
    )
    boundary_id = bootstrap.boundary.boundary_id if bootstrap.boundary else None
    bootstrap.close()

    handle = prepare_service_runtime(
        ServiceRuntimeConfig(
            sqlite_db_path=db_path,
            port=0,
            service_mode="self_hosted",
        ),
        clock=lambda: NOW,
    )
    try:
        with running_runtime(handle):
            permit_status, permit, _ = request_json(
                handle,
                "POST",
                "/v1/enforce",
                headers={
                    "X-Agent-Key": "aak_demo",
                    "X-Vinctor-Boundary-Id": boundary_id or "",
                },
                body={
                    "grant_ref": "grt_demo",
                    "action": "write",
                    "resource": "repo/feature/readme",
                },
            )
            deny_status, deny, _ = request_json(
                handle,
                "POST",
                "/v1/enforce",
                headers={
                    "X-Agent-Key": "aak_demo",
                    "X-Vinctor-Boundary-Id": boundary_id or "",
                },
                body={
                    "grant_ref": "grt_demo",
                    "action": "write",
                    "resource": "repo/other/readme",
                },
            )

        assert permit_status == 200
        assert permit["decision"] == "permit"
        assert deny_status == 403
        assert deny["decision"] == "deny"
        assert deny["error"] == "action_denied"
    finally:
        handle.close()


def test_service_runtime_banner_describes_operational_shape(tmp_path: Path) -> None:
    handle = prepare_service_runtime(
        ServiceRuntimeConfig(
            sqlite_db_path=tmp_path / "vinctor.sqlite",
            port=0,
            service_mode="self_hosted",
            log_level="debug",
        ),
        clock=lambda: NOW,
    )
    try:
        banner = render_service_runtime_banner(handle)
    finally:
        handle.close()

    assert handle.endpoint in banner
    assert "# mode: self_hosted" in banner
    assert "# database: " in banner
    assert "not a hosted production service" in banner
    assert "does not print raw keys" in banner
    assert "aak_" not in banner
    assert "wsk_" not in banner
    assert "grt_" not in banner


def request_json(
    handle: ServiceRuntimeHandle,
    method: str,
    path: str,
    *,
    headers: dict[str, str] | None = None,
    body: object | None = None,
) -> tuple[int, dict[str, Any], str]:
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
    raw = response.read().decode("utf-8")
    conn.close()
    return response.status, json.loads(raw), raw
