# Vinctor MCP Server

The Vinctor MCP server is a read-only control-plane interface over
`vinctor-service`. Use it to inspect what Vinctor knows and decided — grants,
boundaries, and audit events — without ever changing enforcement state.

It is not part of the runtime enforcement path:

```text
hook/plugin -> enforce() -> vinctor-service
```

The MCP path is operator inspection only:

```text
MCP client -> vinctor-mcp-server -> vinctor-service
```

## MVP Scope

The MVP is stdio-only and exposes these tools:

- `vinctor_status`
- `vinctor_list_boundaries`
- `vinctor_get_boundary`
- `vinctor_get_grant`
- `vinctor_list_grants`
- `vinctor_list_audit_events`
- `vinctor_get_audit_event`
- `vinctor_list_grant_requests`
- `vinctor_get_grant_request`
- `vinctor_list_auto_approval_rules`
- `vinctor_explain_denial`
- `vinctor_grant_report`
- `vinctor_boundary_report`

`vinctor_grant_report` and `vinctor_boundary_report` are composite read tools
(the `vinctor_explain_denial` synthesis pattern): they compose existing read
methods and add only fixed string keys plus server-computed integer counts.
`vinctor_grant_report` returns a grant plus its audit timeline partitioned into
lifecycle (issued/revoked) and usage (enforcement decisions) events;
`vinctor_boundary_report` returns a boundary plus a permit/deny summary and its
recent audit events. They add no service surface and inherit the same
allowlist shaping as the underlying read tools.

The server does not expose approve, reject, revoke, grant issuance, rule
mutation, rule evaluation, or `/v1/enforce`.

Boundary explanation is intentionally deferred. A future Phase 2 tool such as
`vinctor_explain_boundary` may summarize boundary status and fail-closed impact,
but the MVP keeps boundary inspection to list/get tools only.

## Configuration

Install the optional MCP dependency when you want to run the server:

```bash
.venv/bin/python -m pip install -e ".[mcp]"
```

Start a local `vinctor-service` first, then point the MCP server at that
service endpoint. For local demos, `vinctor local start` prints the
`VINCTOR_MCP_ENDPOINT` and `VINCTOR_MCP_WORKSPACE_KEY` values to export.

Run over stdio:

```bash
export VINCTOR_MCP_ENDPOINT="http://127.0.0.1:8765"
export VINCTOR_MCP_WORKSPACE_KEY="wsk_..."
export VINCTOR_MCP_TIMEOUT="5"
export VINCTOR_MCP_OUTPUT_MODE="safe"
vinctor-mcp-server
```

Example `.mcp.json` command:

```json
{
  "mcpServers": {
    "vinctor": {
      "command": "/absolute/path/to/vinctor-core/.venv/bin/vinctor-mcp-server",
      "env": {
        "VINCTOR_MCP_ENDPOINT": "http://127.0.0.1:8765",
        "VINCTOR_MCP_WORKSPACE_KEY": "wsk_...",
        "VINCTOR_MCP_TIMEOUT": "5",
        "VINCTOR_MCP_OUTPUT_MODE": "safe"
      }
    }
  }
}
```

Use an absolute venv command or an editable install so the MCP subprocess can
import `vinctor_mcp_server`.

`VINCTOR_MCP_WORKSPACE_KEY` is sent to `vinctor-service` as `X-Workspace-Key`.
Do not pass agent/runtime credentials to the MCP server. The MCP server does
not read `VINCTOR_AGENT_KEY`, does not call `/v1/enforce`, and does not pass
MCP client tokens through to `vinctor-service`.

### Opt-in write tools (Phase 2 safe core)

The server is **read-only by default**. Setting `VINCTOR_MCP_WRITE=1` registers
four additional **operator write tools** — `vinctor_approve_grant_request`,
`vinctor_reject_grant_request`, `vinctor_revoke_grant`, and `vinctor_issue_grant` —
which proxy the workspace-key-authed operator endpoints
(`POST /v1/grant-requests/{id}/approve|reject`, `POST /v1/grants/{grant_ref}/revoke`,
and `POST /v1/grants`). The service authenticates, audits the action (returns
`audit_event_id`), structurally prevents execution agents from approving their own
requests, and enforces the workspace's issuable-scope bounds and max TTL on
issuance; the MCP server mints nothing and adds no new credential. Output is
allowlist-shaped like the read tools. Leave `VINCTOR_MCP_WRITE` unset for a
strictly read-only deployment.

## Model-Visible Output Policy

All MCP tool outputs are model-visible. Every tool response is rebuilt from an
explicit allowlist before it is returned.

`VINCTOR_MCP_OUTPUT_MODE` controls how much authorization detail the MCP server
returns:

- `safe` (default): omits scope lists and denial remediation hints.
- `diagnostic`: includes scope-bearing fields and explicit denial hints for
  operator debugging.

Use `diagnostic` only when the MCP client is trusted to see workspace/admin
authorization details.

Allowed service status fields:

- `status`
- `service`
- `mode`

Allowed boundary fields:

- `boundary_id`
- `name`
- `runtime`
- `boundary_type`
- `mode`
- `status`

Allowed grant fields:

- `grant_id`
- `grant_ref`
- `workspace_id`
- `agent_id`
- `status`
- `expires_at`

Diagnostic-only grant fields:

- `scopes`

`vinctor_list_grants` exposes grant scopes to the MCP client as model-visible
operator data only in `diagnostic` mode. Use diagnostic mode only with
workspace/admin credentials and trusted MCP clients.

Allowed audit event fields:

- `event_id`
- `event_type`
- `decision`
- `reason`
- `workspace_id`
- `agent_id`
- `grant_id`
- `grant_ref`
- `action`
- `resource`
- `boundary_id`
- `runtime`
- `boundary_type`
- `created_at`

Diagnostic-only audit event fields:

- `scope_attempted`
- `scope_matched`

Allowed grant request fields:

- `request_id`
- `workspace_id`
- `requester_agent_id`
- `target_agent_id`
- `requested_ttl_seconds`
- `status`
- `created_at`
- `decided_at`
- `decision_reason`
- `issued_grant_ref`
- `boundary_id`
- `requester_runtime`
- `routing_hint`
- `routing_reason`
- `queue_reason`

Diagnostic-only grant request fields:

- `requested_scopes`

Grant request outputs intentionally omit free-text `reason`, task/session/repo/
worktree metadata, and `decided_by`.

Allowed auto-approval rule fields:

- `rule_id`
- `workspace_id`
- `name`
- `target_agent_id`
- `max_ttl_seconds`
- `status`
- `created_at`
- `updated_at`

Diagnostic-only auto-approval rule fields:

- `allowed_scopes`

Rule outputs intentionally omit `created_by` and `updated_by`.

Allowed list fields such as `scopes`, `requested_scopes`, and `allowed_scopes`
must be arrays of strings. Integer fields such as `requested_ttl_seconds` and
`max_ttl_seconds` must be integers. Other allowed fields must be strings or
`null`. Values with unexpected container types are dropped before returning
model-visible output.

Tool outputs must not expose raw audit payloads, raw prompts, raw tool input,
raw commands, raw keys, key hashes, local database paths, or other service
internals.

In `diagnostic` mode, `vinctor_explain_denial` may include `missing_scope` and
`would_be_allowed_by`. `would_be_allowed_by` contains only grant refs for active,
unexpired grants in the workspace that would match the denied action/resource.
In `safe` mode, these fields are omitted.

## Service Dependencies

The MCP server calls only read-only service APIs:

- `GET /healthz`
- `GET /v1/boundaries`
- `GET /v1/boundaries/{boundary_id}`
- `GET /v1/grants/{grant_ref}`
- `GET /v1/grants` with optional `agent_id` and `status` filters.
- `GET /v1/audit-events` with optional `limit`, `event_type`, `agent_id`,
  `grant_ref`, `boundary_id`, and `request_id` filters. MCP clamps `limit` to
  `1..100` before calling the service.
- `GET /v1/audit-events/{event_id}`
- `GET /v1/grant-requests`
- `GET /v1/grant-requests/{request_id}`
- `GET /v1/auto-approval-rules`

The audit endpoints are workspace-key protected and return the same allowlisted
audit fields as the MCP server.

## Fail-Closed on Unreachable or Hung Upstream

The MCP service client (`VinctorServiceClient`) constructs every connection with
the configured `VINCTOR_MCP_TIMEOUT` (default 5s). When `vinctor-service` is
unreachable or hangs, the client fails closed: it raises rather than returning a
partial or fabricated result, the connection is always closed, and the
workspace key never appears in the surfaced error.

Two failure shapes are covered by regression tests in
`tests/test_mcp_service_client.py`:

- Dead port (nothing listening): the connect attempt fails closed promptly,
  within the timeout budget.
- Hung upstream (a blackhole socket that accepts but never responds): the read
  timeout fires and the call fails closed within the timeout budget, with no
  indefinite hang.

These regressions exercise the real default `HTTPConnection` (honoring the
timeout), not a stubbed connection factory, locking in the dogfood-observed
behavior that a stalled upstream must never hang the caller. A heavier
end-to-end variant over real stdio lives in
`tests/test_mcp_stdio_integration.py`
(`test_real_stdio_hanging_service_fails_closed_with_timeout`).

## Change Record

Context: a dogfood run observed that a stalled/unreachable `vinctor-service`
upstream could hang the MCP caller. The read-only MCP completeness work
(`vinctor_list_grants`, `GET /v1/grants` list, `would_be_allowed_by` in
`vinctor_explain_denial`, and the `audit export --format jsonl` operator
command) was already shipped; the remaining gap was a fail-closed regression at
the client's real socket level.

What this change does: adds two real-socket regression tests for the MCP service
client — a dead port (nothing listening) and a blackhole socket (accepts, never
responds) — asserting the client fails closed within the timeout budget without
hanging and without leaking the workspace key. Documents the fail-closed
timeout invariant here.

Next steps: pydantic validation-error string sanitization remains a separate
deferred hardening slice (SDK-entangled) and is intentionally out of scope here.
