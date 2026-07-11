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
    assert result["hook_config_path"] == str(tmp_path / "claude-code-hook.json")

    hook_config = (tmp_path / "claude-code-hook.json").read_text(encoding="utf-8")
    assert '"tool": "Write"' in hook_config
    assert '"tool": "Edit"' in hook_config
    assert '"tool": "Bash"' in hook_config
    assert '"pattern": "**/repo/design-partner/feature/**"' in hook_config
    assert '"pattern": "echo test-ok"' in hook_config
    assert '"resource": "repo/design-partner/feature/README.md"' in hook_config

    handle = module.prepare_design_partner_e2e(
        module.E2EConfig(db_path=tmp_path / "serve.sqlite", port=0),
        now=NOW,
    )
    try:
        instructions = module.render_operator_instructions(handle)
    finally:
        module.close_design_partner_e2e(handle)

    assert "VINCTOR_CLAUDE_CODE_HOOK_CONFIG" in instructions
    assert str(tmp_path / "claude-code-hook.json") in instructions
    assert "Hook config written to:" in instructions


def test_hook_config_path_is_absolute_even_with_relative_db(
    tmp_path: Path, monkeypatch
) -> None:
    # The site guide runs Claude Code from a *disposable* workspace, so the exported
    # VINCTOR_CLAUDE_CODE_HOOK_CONFIG must be absolute — a relative path would
    # resolve against the wrong cwd and the hook would not find its config.
    module = _load_setup_module()
    monkeypatch.chdir(tmp_path)

    handle = module.prepare_design_partner_e2e(
        module.E2EConfig(db_path=Path("workdir/serve.sqlite"), port=0),
        now=NOW,
    )
    try:
        assert handle.hook_config_path.is_absolute()
        instructions = module.render_operator_instructions(handle)
    finally:
        module.close_design_partner_e2e(handle)

    export_line = next(
        line
        for line in instructions.splitlines()
        if "export VINCTOR_CLAUDE_CODE_HOOK_CONFIG=" in line
    )
    value = export_line.split("=", 1)[1].strip().strip('"').strip("'")
    assert Path(value).is_absolute(), export_line


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
    assert "VINCTOR_CLAUDE_CODE_HOOK_CONFIG" in text
    assert ".venv/bin/python" in text
    assert "without the hook config" in text
    assert "unmapped -> ask" in text
    assert "new file" in text
    assert "fixed test clock" in text
    assert "This is not an official Claude Code integration" in text
    assert "This is not a production readiness claim" in text


def _load_setup_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("claude_code_e2e_setup", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
