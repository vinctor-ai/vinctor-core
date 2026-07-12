# Open Issues — vinctor-core
Living tracker so already-fixed items are not re-worked. Code is the source of truth for "resolved" — re-verify before re-routing.

## Open
- (none currently tracked — add as discovered)

## Recently resolved — do NOT re-route
- F1 (2026-06-18): design-partner E2E setup helper now writes the hook config and exports VINCTOR_CLAUDE_CODE_HOOK_CONFIG (demo/claude_code_design_partner_e2e_setup.py).
- F6 (2026-06-18): vinctor_mcp_server/server.py has a __main__ guard — `python -m vinctor_mcp_server.server` serves over stdio.
- local-start UX (this PR): EADDRINUSE on a busy port exits with a friendly CliError instead of a raw traceback; restart hint emits `vinctor local start …`; corrected the "fixed test clock" note (frozen clock is pytest-only).
