# Vinctor MCP Server

The Vinctor MCP server is a read-only control-plane interface over
`vinctor-service`.

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
        "VINCTOR_MCP_TIMEOUT": "5"
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

## Model-Visible Output Policy

All MCP tool outputs are model-visible. Every tool response is rebuilt from an
explicit allowlist before it is returned.

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
- `scopes`
- `status`
- `expires_at`

`vinctor_list_grants` exposes grant scopes to the MCP client as model-visible
operator data. Use it only with workspace/admin credentials and the same output
allowlist as single-grant lookup.

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
- `scope_attempted`
- `scope_matched`
- `boundary_id`
- `runtime`
- `boundary_type`
- `created_at`

Allowed grant request fields:

- `request_id`
- `workspace_id`
- `requester_agent_id`
- `target_agent_id`
- `requested_scopes`
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

Grant request outputs intentionally omit free-text `reason`, task/session/repo/
worktree metadata, and `decided_by`.

Allowed auto-approval rule fields:

- `rule_id`
- `workspace_id`
- `name`
- `target_agent_id`
- `allowed_scopes`
- `max_ttl_seconds`
- `status`
- `created_at`
- `updated_at`

Rule outputs intentionally omit `created_by` and `updated_by`.

Allowed list fields such as `scopes`, `requested_scopes`, and `allowed_scopes`
must be arrays of strings. Integer fields such as `requested_ttl_seconds` and
`max_ttl_seconds` must be integers. Other allowed fields must be strings or
`null`. Values with unexpected container types are dropped before returning
model-visible output.

Tool outputs must not expose raw audit payloads, raw prompts, raw tool input,
raw commands, raw keys, key hashes, local database paths, or other service
internals.

`vinctor_explain_denial` may include `missing_scope` and
`would_be_allowed_by`. `would_be_allowed_by` contains only grant refs for active,
unexpired grants in the workspace that would match the denied action/resource.

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
