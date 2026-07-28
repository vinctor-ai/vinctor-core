# Claude Code E2E Proof Worksheet - 2.1.169

Status: reproducible setup plus operator evidence worksheet. The automated
setup in this repository proves local service provisioning, service-issued
grant creation, permit, deny, and audit behavior. A human operator still needs
to run the Claude Code session and paste observed evidence into the sections
below.

This is not an official Claude Code integration. This is not a production
readiness claim. This is not a production readiness claim for Vinctor or the
Claude Code hook boundary.

## Scope

This artifact fixes one narrow proof target:

```text
Claude Code 2.1.169
-> measured PreToolUse hook boundary
-> vinctor-service /v1/enforce
-> action_permitted + action_denied audit events
-> operator inspection through audit API and MCP
```

It does not claim complete Claude Code coverage, hosted service behavior,
approval workflow behavior, credential shielding, JIT orchestration, sandboxing,
raw interception, provider integration, or production readiness.

## Pinned Inputs

| Input | Value |
| --- | --- |
| Claude Code runtime | `Claude Code 2.1.169` |
| Hook package | `vinctor-claude-code-hook 0.3.0-preview.3` |
| Hook coverage source | `vinctor-claude-code-hook/docs/validation/coverage-matrix-claude-code-2.1.169-2026-06-11.md` |
| Vinctor service | local `vinctor service serve` equivalent from this repository |
| Grant issuance | `POST /v1/grants` with `X-Workspace-Key` |
| Runtime enforce | strict `POST /v1/enforce` body: `grant_ref`, `action`, `resource` |
| MCP output mode | `safe` for model-facing inspection, `diagnostic` for operator-only denial investigation |

## Coverage Boundary

Claims in this worksheet are capped by the measured coverage matrix:

- `Bash`, `Read`, `Write`, `Edit`, `WebFetch`, and `WebSearch` emitted
  `PreToolUse` events in Claude Code 2.1.169.
- `MultiEdit` was not observed as a distinct runtime tool in Claude Code
  2.1.169; the model fell back to `Edit`.
- MCP tool emission was unmeasured in that coverage run.
- The Bash first-token limitation applies: wrappers such as `sudo npm publish`
  and `bash -c "npm publish"` fall to `ask`, while some compound commands
  classify only the first segment. Do not claim per-segment Bash authorization.

## Automated Local Setup

Run from `vinctor-core`:

```bash
.venv/bin/python demo/claude_code_design_partner_e2e_setup.py \
  --db .vinctor/design-partner-claude-code.sqlite \
  --port 8765 \
  --hook-cli /absolute/path/to/vinctor-claude-code-hook/dist/src/cli.js \
  --serve
```

Use Python 3.11 or newer. The repository virtual environment command above is
preferred so the helper runs with the same interpreter used by the test suite.

The setup process:

1. creates local workspace and agent keys;
2. stores only key hashes and metadata in SQLite;
3. sets issuer bounds for the Claude Code agent;
4. starts the local Vinctor HTTP service;
5. registers a `claude-code` / `pretooluse` boundary;
6. issues the partner grant through `POST /v1/grants`;
7. writes a Claude Code hook mapping config for the worksheet paths.

It prints `VINCTOR_ENDPOINT`, `VINCTOR_AGENT_KEY`, `VINCTOR_GRANT_REF`,
`VINCTOR_WORKSPACE_KEY`, `VINCTOR_CLAUDE_CODE_HOOK_CONFIG`, optional
`VINCTOR_BOUNDARY_ID`, and a Claude Code `settings.json` hook snippet. Store raw
keys outside the repository. Do not paste raw keys into model-facing prompts.

The generated hook config is required for this worksheet. In practical terms:
without the hook config, `repo/design-partner/...` paths are unmapped -> ask,
`/v1/enforce` is not called, and no Vinctor action audit event is produced. The
helper writes the config path printed in `VINCTOR_CLAUDE_CODE_HOOK_CONFIG`.

The generated rules intentionally map fixed action/resource strings, not
wildcard resources:

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "Write",
      "matchType": "glob",
      "pattern": "**/repo/design-partner/feature/**",
      "action": "write",
      "resource": "repo/design-partner/feature/README.md"
    },
    {
      "tool": "Edit",
      "matchType": "glob",
      "pattern": "**/repo/design-partner/feature/**",
      "action": "write",
      "resource": "repo/design-partner/feature/README.md"
    },
    {
      "tool": "Write",
      "matchType": "glob",
      "pattern": "**/repo/design-partner/protected/**",
      "action": "write",
      "resource": "repo/design-partner/protected/README.md"
    },
    {
      "tool": "Edit",
      "matchType": "glob",
      "pattern": "**/repo/design-partner/protected/**",
      "action": "write",
      "resource": "repo/design-partner/protected/README.md"
    },
    {
      "tool": "Read",
      "matchType": "glob",
      "pattern": "**/repo/design-partner/protected/**",
      "action": "read",
      "resource": "repo/design-partner/protected/README.md"
    },
    {
      "tool": "Bash",
      "matchType": "exact",
      "pattern": "echo test-ok",
      "action": "execute",
      "resource": "ci/test"
    }
  ]
}
```

Automated service smoke, without running Claude Code:

```bash
.venv/bin/python demo/claude_code_design_partner_e2e_setup.py \
  --db /tmp/vinctor-claude-code-e2e.sqlite \
  --port 0
```

Expected final line:

```text
ALL CLAUDE CODE DESIGN-PARTNER SETUP STEPS PASSED
```

That smoke proves service setup, API grant issuance, permit, deny, and audit
recording. It does not prove a live Claude Code session.

## Claude Code Hook Wiring

Build the measured hook repo:

```bash
cd /absolute/path/to/vinctor-claude-code-hook
npm install
npm run build
claude --version
```

Record `claude --version` in the evidence section. It must be
`Claude Code 2.1.169` for this worksheet's claim.

Use the `settings.json` snippet printed by the setup script. The matcher should
remain:

```text
Bash|Read|Write|Edit|MultiEdit|WebFetch|WebSearch|mcp__.*
```

The hook is consumed as-is. Do not modify hook code for this proof. If the
session requires a hook change, stop and file that as a separate finding.

Required Claude Code session environment:

```bash
export VINCTOR_ENDPOINT="http://127.0.0.1:8765"
export VINCTOR_AGENT_KEY="aak_..."
export VINCTOR_GRANT_REF="grt_..."
export VINCTOR_CLAUDE_CODE_HOOK_CONFIG="/absolute/path/to/claude-code-hook.json"
export VINCTOR_BOUNDARY_ID="bnd_..."
```

## Manual Claude Code Session

Run this in a disposable repository or worktree.

### ALLOW path

Ask Claude Code to make a scoped file change:

```text
Create a new file at repo/design-partner/feature/README.md and then run echo test-ok.
```

Expected result:

- `Write` for the new file at `repo/design-partner/feature/README.md` reaches
  the hook and maps to `write:repo/design-partner/feature/README.md`.
- Vinctor returns permit.
- Claude Code executes the tool.
- Audit includes an `action_permitted` event.
- The follow-up `echo test-ok` reaches the hook and maps to `execute:ci/test`,
  which is also covered by the issued grant.

Paste observed evidence:

```text
Claude Code version:
Hook commit/package:
Vinctor core commit:
ALLOW observed tool:
ALLOW hook decision:
ALLOW audit_event_id:
ALLOW notes:
```

### DENY path

Ask Claude Code to write outside the scoped path:

```text
Create a new file at repo/design-partner/protected/README.md.
```

Expected result:

- `Write` for the new file at `repo/design-partner/protected/README.md`
  reaches the hook and maps to `write:repo/design-partner/protected/README.md`.
- Vinctor returns deny with `action_denied`.
- Claude Code blocks execution through the hook decision.
- Audit includes an `action_denied` event.

Use a new file for the cleanest deny observation. If the runtime reads an
existing protected file before writing, the generated protected `Read` rule may
deny earlier with a read-scope failure. That is still Vinctor enforcement, but
it is not the clean write-deny proof target for this worksheet.

Paste observed evidence:

```text
DENY observed tool:
DENY hook decision:
DENY audit_event_id:
DENY notes:
```

## Operator Audit Evidence

Use the workspace key only from an operator shell:

```bash
curl -sS "$VINCTOR_ENDPOINT/v1/audit-events?grant_ref=$VINCTOR_GRANT_REF&limit=20" \
  -H "X-Workspace-Key: $VINCTOR_WORKSPACE_KEY"
```

Expected event types:

```text
grant_issued
action_permitted
action_denied
```

Paste audit evidence:

```text
action_permitted event_id:
action_permitted action/resource:
action_denied event_id:
action_denied action/resource:
boundary_id/runtime/boundary_type:
```

## MCP Evidence: Safe Then Diagnostic

The MCP server is operator inspection only. It is not in the runtime enforcement
path and it does not call `/v1/enforce`.

Start MCP in safe mode first:

```bash
export VINCTOR_MCP_ENDPOINT="$VINCTOR_ENDPOINT"
export VINCTOR_MCP_WORKSPACE_KEY="$VINCTOR_WORKSPACE_KEY"
export VINCTOR_MCP_OUTPUT_MODE="safe"
vinctor-mcp-server
```

Through the MCP client, call:

```text
vinctor_list_audit_events grant_ref=<VINCTOR_GRANT_REF>
vinctor_explain_denial event_id=<action_denied event id>
```

Expected safe-mode observation:

- the denial is visible;
- `missing_scope` is not returned;
- `would_be_allowed_by` is not returned.

For operator-only investigation, stop the MCP server and restart it in
diagnostic mode. `VINCTOR_MCP_OUTPUT_MODE` is read when the MCP server starts;
changing the environment does not affect an already-running server.

```bash
export VINCTOR_MCP_OUTPUT_MODE="diagnostic"
vinctor-mcp-server
```

MCP server must be restarted before diagnostic output is available.

Call `vinctor_explain_denial` again. Expected diagnostic-mode observation:

- `missing_scope` shows the denied action/resource scope;
- `would_be_allowed_by` appears only if another active, unexpired grant in the
  same workspace would cover the denied action/resource.

Paste MCP evidence:

```text
safe mode result omitted missing_scope/would_be_allowed_by:
diagnostic mode missing_scope:
diagnostic mode would_be_allowed_by:
```

## Honesty Notes

- The automated setup script proves local service behavior and API-issued grant
  lifecycle, not a live Claude Code run.
- The fixed test clock is supplied only by the pytest suite; the documented
  smoke command above runs the real CLI with the real wall clock, so its audit
  timestamps are real-time. Either way, TTL expiry by waiting is not the proof
  target here — use revoke/lifecycle-specific tests for expiry behavior.
- The Claude Code proof is valid only after the manual evidence sections are
  filled with observations from Claude Code 2.1.169.
- `ask` is not a Vinctor permit or deny; it means the hook abstained and Claude
  Code's native permission flow took over.
- For this worksheet, unmapped -> ask means the hook config was not loaded or
  did not match the runtime tool event; fix the mapping before claiming
  Vinctor allow/deny behavior.
- Do not claim coverage for `MultiEdit` as a distinct tool in Claude Code
  2.1.169.
- Do not claim MCP runtime coverage from this worksheet.
- Do not claim complete Bash coverage because the bash first-token limitation is
  known and measured.
