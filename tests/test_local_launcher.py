from __future__ import annotations

import json
import socket
import sqlite3
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from pathlib import Path
from threading import Thread

import pytest

from vinctor_service.cli import EXIT_SERVICE, CliError
from vinctor_service.local_launcher import (
    LocalLaunchConfig,
    prepare_local_service,
    render_env_exports,
    serve_local_service,
)

NOW = datetime(2026, 6, 10, 12, 0, tzinfo=UTC)


def test_prepare_local_service_bootstraps_sqlite_service(tmp_path: Path) -> None:
    db_path = tmp_path / "vinctor.sqlite"

    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=db_path,
            port=0,
            workspace_id="ws_demo",
            agent_id="agent_release",
            workspace_key="wsk_demo",
            agent_key="aak_demo",
            grant_ref="grt_demo",
            scopes=("write:repo/feature/*",),
            boundary_name="claude-code-local",
        ),
        now=NOW,
    )
    try:
        grant = handle.service.grant_repository.get_by_ref("grt_demo")

        assert db_path.exists()
        assert handle.endpoint.startswith("http://127.0.0.1:")
        assert handle.workspace_key == "wsk_demo"
        assert handle.agent_key == "aak_demo"
        assert handle.grant_ref == "grt_demo"
        assert handle.grant_expires_at == NOW + timedelta(hours=8)
        assert not handle.generated_workspace_key
        assert not handle.generated_agent_key
        assert handle.boundary is not None
        assert handle.boundary.boundary_id.startswith("bnd_")
        assert grant is not None
        assert grant.workspace_id == "ws_demo"
        assert grant.agent_id == "agent_release"
        assert grant.scopes == ("write:repo/feature/*",)
    finally:
        handle.close()


def test_render_env_exports_includes_copy_pasteable_hook_values(
    tmp_path: Path,
) -> None:
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "vinctor.sqlite",
            port=0,
            workspace_key="wsk_demo",
            agent_key="aak_demo",
            grant_ref="grt_demo",
            boundary_name="claude-code-local",
        ),
        now=NOW,
    )
    try:
        exports = render_env_exports(handle, now=NOW)
    finally:
        handle.close()

    assert f'export VINCTOR_ENDPOINT="{handle.endpoint}"' in exports
    assert 'export VINCTOR_AGENT_KEY="aak_demo"' in exports
    assert 'export VINCTOR_GRANT_REF="grt_demo"' in exports
    assert 'export VINCTOR_WORKSPACE_KEY="wsk_demo"' in exports
    assert 'export VINCTOR_BOUNDARY_ID="' in exports
    assert "# Grant expires at 2026-06-10T20:00:00+00:00." in exports
    assert "# Restart with explicit keys:" in exports
    assert "# vinctor local start \\" in exports
    assert "#   --db " in exports
    assert '#   --workspace-key "$VINCTOR_WORKSPACE_KEY" \\' in exports
    assert '#   --agent-key "$VINCTOR_AGENT_KEY" \\' in exports
    assert '#   --grant-ref "$VINCTOR_GRANT_REF" \\' in exports
    assert '#   --boundary-name "claude-code-local"' in exports
    assert "# fallback: python -m vinctor_service.local_launcher ..." in exports
    assert "X-Vinctor-Boundary-Id" in exports


def test_render_env_exports_warns_when_grant_is_expired(
    tmp_path: Path,
) -> None:
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "vinctor.sqlite",
            port=0,
            workspace_key="wsk_demo",
            agent_key="aak_demo",
            grant_ref="grt_demo",
            boundary_name="claude-code-local",
        ),
        now=NOW,
    )
    try:
        exports = render_env_exports(handle, now=NOW + timedelta(hours=9))
    finally:
        handle.close()

    assert "# WARNING: this grant is expired; /v1/enforce will deny" in exports


def test_prepare_local_service_reuses_existing_grant_and_boundary(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    config = LocalLaunchConfig(
        db_path=db_path,
        port=0,
        workspace_id="ws_demo",
        agent_id="agent_release",
        grant_ref="grt_demo",
        scopes=("write:repo/feature/*",),
        boundary_name="claude-code-local",
    )

    first = prepare_local_service(config, now=NOW)
    first_boundary_id = first.boundary.boundary_id if first.boundary else None
    first.close()

    second = prepare_local_service(config, now=NOW)
    try:
        assert second.boundary is not None
        assert second.boundary.boundary_id == first_boundary_id
        conn = sqlite3.connect(db_path)
        try:
            grant_count = conn.execute("SELECT COUNT(*) FROM grants").fetchone()[0]
            boundary_count = conn.execute("SELECT COUNT(*) FROM boundaries").fetchone()[0]
        finally:
            conn.close()
        assert grant_count == 1
        assert boundary_count == 1
    finally:
        second.close()


def test_prepare_local_service_reuses_explicit_durable_keys(
    tmp_path: Path,
) -> None:
    db_path = tmp_path / "vinctor.sqlite"
    config = LocalLaunchConfig(
        db_path=db_path,
        port=0,
        workspace_key="wsk_demo",
        agent_key="aak_demo",
        boundary_name="claude-code-local",
    )

    first = prepare_local_service(config, now=NOW)
    first.close()

    second = prepare_local_service(config, now=NOW)
    try:
        conn = sqlite3.connect(db_path)
        try:
            key_count = conn.execute("SELECT COUNT(*) FROM local_keys").fetchone()[0]
            raw_key_count = conn.execute(
                """
                SELECT COUNT(*)
                FROM local_keys
                WHERE key_hash IN ('wsk_demo', 'aak_demo')
                """
            ).fetchone()[0]
        finally:
            conn.close()

        assert second.workspace_key == "wsk_demo"
        assert second.agent_key == "aak_demo"
        assert key_count == 2
        assert raw_key_count == 0
    finally:
        second.close()


def test_serve_local_service_raises_cli_error_on_busy_port(tmp_path: Path) -> None:
    busy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    busy.bind(("127.0.0.1", 0))
    busy.listen(1)
    port = busy.getsockname()[1]
    try:
        with pytest.raises(CliError) as exc_info:
            serve_local_service(
                LocalLaunchConfig(
                    db_path=tmp_path / "vinctor.sqlite",
                    port=port,
                    workspace_key="wsk_demo",
                    agent_key="aak_demo",
                    grant_ref="grt_demo",
                )
            )
    finally:
        busy.close()

    assert exc_info.value.code == EXIT_SERVICE
    assert f"port {port} already in use" in str(exc_info.value)
    assert "--port" in str(exc_info.value)


def test_prepare_local_service_rejects_invalid_scope(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid grant scope"):
        prepare_local_service(
            LocalLaunchConfig(
                db_path=tmp_path / "vinctor.sqlite",
                scopes=("write:repo",),
            ),
            now=NOW,
        )


def test_prepared_service_accepts_hook_shaped_enforce_request(
    tmp_path: Path,
) -> None:
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "vinctor.sqlite",
            port=0,
            workspace_id="ws_demo",
            agent_id="agent_release",
            agent_key="aak_demo",
            grant_ref="grt_demo",
            scopes=("write:repo/feature/*",),
            boundary_name="claude-code-local",
        ),
        now=NOW,
    )
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        host, port_text = handle.endpoint.removeprefix("http://").split(":")
        conn = HTTPConnection(host, int(port_text), timeout=5)
        conn.request(
            "POST",
            "/v1/enforce",
            body=json.dumps(
                {
                    "grant_ref": handle.grant_ref,
                    "action": "write",
                    "resource": "repo/feature/readme",
                }
            ),
            headers={
                "Content-Type": "application/json",
                "X-Agent-Key": handle.agent_key,
                "X-Vinctor-Boundary-Id": handle.boundary.boundary_id
                if handle.boundary
                else "",
            },
        )
        response = conn.getresponse()
        body = json.loads(response.read().decode("utf-8"))
        conn.close()

        assert response.status == 200
        assert body["decision"] == "permit"
        assert handle.service.audit_events[-1].boundary_id == handle.boundary.boundary_id
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()
