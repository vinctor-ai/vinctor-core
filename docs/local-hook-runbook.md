# Local Hook Integration Runbook

This runbook shows how to connect a local Vinctor service to a runtime hook for
demo and dogfooding. It does not require changing hook repositories.

## 1. Start A Local Service

Install the package in editable mode, then start the local prototype service:

```bash
vinctor local start \
  --db .vinctor-local.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-name claude-code-local \
  --scope execute:ci/test
```

For the first run, omit explicit keys and copy the printed exports. For repeat
runs, pass copied keys back explicitly or use:

```bash
vinctor local env \
  --db .vinctor-local.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-name claude-code-local
```

## 2. Export Runtime Values

The hook runtime needs:

```bash
export VINCTOR_ENDPOINT="http://127.0.0.1:8765"
export VINCTOR_AGENT_KEY="aak_..."
export VINCTOR_GRANT_REF="grt_..."
export VINCTOR_BOUNDARY_ID="bnd_..."
```

`VINCTOR_BOUNDARY_ID` is optional for enforcement, but useful for audit rows
because it records which configured runtime boundary originated the check.

## 3. Trigger A Hook-Enforced Action

Use a runtime hook that maps a tool call to a Vinctor action/resource. Examples:

- Claude Code hook maps selected `PreToolUse` calls.
- Codex hook maps selected Codex tool calls.
- Hermes plugin maps selected Hermes tool calls.

Keep runtime-specific config in the hook/plugin repo. The core repo owns the
local service, grant lifecycle, and audit behavior.

## 4. Inspect Audit

```bash
vinctor --db .vinctor-local.sqlite operator audit list --limit 20
vinctor --db .vinctor-local.sqlite operator audit list --boundary-id "$VINCTOR_BOUNDARY_ID"
```

Expected permit/deny rows include:

- `event_type`
- `decision`
- `agent_id`
- `grant_ref`
- `action`
- `resource`
- `boundary_id`

## Boundaries

The hook remains enforce-only. It should not issue grants, create rules, or
approve requests. Those actions belong to workspace/admin authority through
`vinctor operator ...` or future orchestrator/human approval surfaces.
