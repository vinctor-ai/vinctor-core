from __future__ import annotations

import importlib.util
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "demo" / "claude_code_design_partner_e2e_setup.py"
DOC_PATH = (
    ROOT
    / "docs"
    / "design-partner"
    / "end-to-end-claude-code-2.1.169-2026-06-12.md"
)
NOW = datetime(2026, 6, 12, 12, 0, tzinfo=UTC)


def test_claude_code_design_partner_setup_uses_service_grant_api(tmp_path: Path) -> None:
    module = _load_setup_module()

    result = module.run_automated_proof(
        module.E2EConfig(
            db_path=tmp_path / "vinctor.sqlite",
            port=0,
            workspace_id="ws_design_partner",
            agent_id="agent_claude_code",
            scopes=("write:repo/design-partner/feature/*", "execute:ci/test"),
            permit_action="write",
            permit_resource="repo/design-partner/feature/README.md",
            deny_action="write",
            deny_resource="repo/design-partner/protected/README.md",
        ),
        now=NOW,
    )

    assert result["grant_issued_via"] == "POST /v1/grants"
    assert result["permit_decision"] == "permit"
    assert result["deny_decision"] == "deny"
    assert result["audit_event_types"][-2:] == ["action_permitted", "action_denied"]
    assert result["boundary_runtime"] == "claude-code"
    assert result["boundary_type"] == "pretooluse"


def test_claude_code_design_partner_doc_keeps_claims_narrow() -> None:
    text = DOC_PATH.read_text(encoding="utf-8")

    assert "Claude Code 2.1.169" in text
    assert "coverage-matrix-claude-code-2.1.169-2026-06-11.md" in text
    assert "0.3.0-preview.3" in text
    assert "action_permitted" in text
    assert "action_denied" in text
    assert "MultiEdit" in text and "not observed" in text
    assert "bash first-token" in text
    assert "MCP server must be restarted" in text
    assert 'VINCTOR_MCP_OUTPUT_MODE="safe"' in text
    assert 'VINCTOR_MCP_OUTPUT_MODE="diagnostic"' in text
    assert "missing_scope" in text
    assert "would_be_allowed_by" in text
    assert "This is not an official Claude Code integration" in text
    assert "This is not a production readiness claim" in text


def _load_setup_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("claude_code_e2e_setup", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
