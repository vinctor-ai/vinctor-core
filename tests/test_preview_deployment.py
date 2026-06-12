from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from threading import Thread
from types import ModuleType

import yaml

from vinctor_service.local_launcher import LocalLaunchConfig, prepare_local_service

ROOT = Path(__file__).resolve().parents[1]
PREVIEW_DIR = ROOT / "deploy" / "preview"
NOW = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)


def test_preview_compose_routes_tls_through_caddy_to_internal_service() -> None:
    compose = yaml.safe_load((PREVIEW_DIR / "compose.yaml").read_text(encoding="utf-8"))

    services = compose["services"]
    vinctor = services["vinctor"]
    caddy = services["caddy"]

    assert vinctor["command"] == ["vinctor", "service", "serve"]
    assert vinctor["restart"] == "unless-stopped"
    assert vinctor["expose"] == ["8765"]
    assert "ports" not in vinctor
    assert "vinctor-data:/data" in vinctor["volumes"]
    assert vinctor["environment"]["VINCTOR_DB"] == "/data/vinctor.sqlite"
    assert vinctor["environment"]["VINCTOR_SERVICE_MODE"] == "self_hosted"
    assert "/healthz" in " ".join(vinctor["healthcheck"]["test"])

    assert caddy["image"].startswith("caddy:")
    assert caddy["restart"] == "unless-stopped"
    assert any(port.endswith(":80") for port in caddy["ports"])
    assert any(port.endswith(":443") for port in caddy["ports"])
    assert caddy["depends_on"]["vinctor"]["condition"] == "service_healthy"
    assert "./Caddyfile:/etc/caddy/Caddyfile:ro" in caddy["volumes"]

    assert "vinctor-data" in compose["volumes"]
    assert "caddy-data" in compose["volumes"]


def test_preview_env_example_does_not_store_raw_keys() -> None:
    env_example = (PREVIEW_DIR / ".env.example").read_text(encoding="utf-8")

    assert "VINCTOR_DB=/data/vinctor.sqlite" in env_example
    assert "VINCTOR_PREVIEW_HOSTNAME=localhost" in env_example
    assert "VINCTOR_WORKSPACE_KEY" not in env_example
    assert "VINCTOR_AGENT_KEY" not in env_example
    assert "VINCTOR_GRANT_REF" not in env_example
    assert "wsk_" not in env_example
    assert "aak_" not in env_example
    assert "grt_" not in env_example


def test_preview_smoke_checks_health_enforce_and_audit(tmp_path: Path) -> None:
    smoke = _load_smoke_module()
    handle = prepare_local_service(
        LocalLaunchConfig(
            db_path=tmp_path / "vinctor.sqlite",
            port=0,
            workspace_id="ws_preview",
            agent_id="agent_partner",
            workspace_key="wsk_preview",
            agent_key="aak_preview",
            grant_ref="grt_preview",
            scopes=("write:repo/feature/*",),
            boundary_name="codex-preview",
        ),
        now=NOW,
    )
    boundary_id = handle.boundary.boundary_id if handle.boundary else None
    thread = Thread(target=handle.server.serve_forever, daemon=True)
    thread.start()
    try:
        result = smoke.run_smoke(
            smoke.SmokeConfig(
                endpoint=handle.endpoint,
                agent_key="aak_preview",
                workspace_key="wsk_preview",
                grant_ref="grt_preview",
                permit_action="write",
                permit_resource="repo/feature/readme",
                deny_action="write",
                deny_resource="repo/other/readme",
                boundary_id=boundary_id,
            )
        )
    finally:
        handle.server.shutdown()
        thread.join(timeout=5)
        handle.close()

    assert result["health_status"] == "ok"
    assert result["permit_decision"] == "permit"
    assert result["deny_decision"] == "deny"
    assert result["audit_event_count"] >= 2
    assert result["permit_audit_event_id"] is not None
    assert result["deny_audit_event_id"] is not None


def _load_smoke_module() -> ModuleType:
    path = PREVIEW_DIR / "smoke.py"
    spec = importlib.util.spec_from_file_location("vinctor_preview_smoke", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
