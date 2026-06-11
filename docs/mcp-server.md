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
- `vinctor_list_audit_events`
- `vinctor_get_audit_event`
- `vinctor_explain_denial`

The server does not expose approve, reject, revoke, grant issuance, rule
management, or `/v1/enforce`.

## Configuration

Install the optional MCP dependency when you want to run the server:

```bash
.venv/bin/python -m pip install -e ".[mcp]"
```

Run over stdio:

```bash
export VINCTOR_MCP_ENDPOINT="http://127.0.0.1:8765"
export VINCTOR_MCP_WORKSPACE_KEY="wsk_..."
vinctor-mcp-server
```

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

Tool outputs must not expose raw audit payloads, raw prompts, raw tool input,
raw commands, raw keys, key hashes, local database paths, or other service
internals.

## Service Dependencies

The MCP server calls only read-only service APIs:

- `GET /healthz`
- `GET /v1/boundaries`
- `GET /v1/boundaries/{boundary_id}`
- `GET /v1/grants/{grant_ref}`
- `GET /v1/audit-events`
- `GET /v1/audit-events/{event_id}`

The audit endpoints are workspace-key protected and return the same allowlisted
audit fields as the MCP server.
