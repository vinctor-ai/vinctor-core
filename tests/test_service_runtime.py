from __future__ import annotations

import json
import socket
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from vinctor_service.cli import EXIT_SERVICE, CliError
from vinctor_service.keys import SQLiteLocalKeyRepository
from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service
from vinctor_service.service_config import ServiceRuntimeConfig
from vinctor_service.service_runtime import (
    ServiceRuntimeHandle,
    prepare_service_runtime,
    render_service_runtime_banner,
    serve_service_runtime,
)
from vinctor_service.sqlite import SQLiteV1Service

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


def test_serve_service_runtime_raises_cli_error_on_busy_port(tmp_path: Path) -> None:
    busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    port = busy.getsockname()[1]
    try:
        with pytest.raises(CliError) as exc_info:
            serve_service_runtime(
                ServiceRuntimeConfig(
                    sqlite_db_path=tmp_path / "vinctor.sqlite",
                    port=port,
                    service_mode="self_hosted",
                )
            )
    finally:
        busy.close()

    assert exc_info.value.code == EXIT_SERVICE
    assert f"port {port} already in use" in str(exc_info.value)
    assert "--port" in str(exc_info.value)


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


def test_service_runtime_wires_delegated_pep_enforce(tmp_path: Path) -> None:
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
    bootstrap.close()

    # Provision a PEP key for the workspace (no operator HTTP path exists yet).
    conn = sqlite3.connect(db_path)
    SQLiteV1Service(conn)
    SQLiteLocalKeyRepository(conn).create_pep_key(
        workspace_id="ws_demo", pep_id="pep_runner", raw_key="pep_runner", now=NOW
    )
    conn.commit()
    conn.close()

    handle = prepare_service_runtime(
        ServiceRuntimeConfig(sqlite_db_path=db_path, port=0, service_mode="self_hosted"),
        clock=lambda: NOW,
    )
    try:
        with running_runtime(handle):
            permit_status, permit, _ = request_json(
                handle,
                "POST",
                "/v1/enforce/delegated",
                headers={"X-PEP-Key": "pep_runner"},
                body={
                    "workspace_id": "ws_demo",
                    "agent_id": "agent_runner",
                    "grant_ref": "grt_demo",
                    "action": "write",
                    "resource": "repo/feature/readme",
                },
            )
            foreign_status, foreign, _ = request_json(
                handle,
                "POST",
                "/v1/enforce/delegated",
                headers={"X-PEP-Key": "pep_runner"},
                body={
                    "workspace_id": "ws_other",
                    "agent_id": "agent_runner",
                    "grant_ref": "grt_demo",
                    "action": "write",
                    "resource": "repo/feature/readme",
                },
            )

        # The resolver is wired: a real PEP key now authorizes its own workspace.
        assert permit_status == 200
        assert permit["decision"] == "permit"
        # A foreign asserted workspace is forced to the PEP's own -> forbidden.
        assert foreign_status in (403, 404)
        assert foreign.get("decision") != "permit"
    finally:
        handle.close()


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
