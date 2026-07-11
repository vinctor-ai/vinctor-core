# Troubleshooting Operator Policy

## A Mapped Call Was Denied

Check:

- the hook mapped the call to the expected action/resource pair
- the active grant contains that exact scope or a matching terminal wildcard
- the grant is active and unexpired
- the boundary is enabled
- the mapping and grant use the same action/resource identifier

## A Call Asked Or Abstained Instead Of Denying

The call was probably unmapped.

Check:

- the runtime tool name is correct
- the rule `pattern` matches the normalized input used by that tool
- the MCP server/tool name is exact
- `inputField` is top-level, present, non-empty, and a string
- the runtime actually emits a boundary event for that tool path

## A Call Was Permitted Unexpectedly

Check:

- broad grant scopes such as `write:repo/*`
- operator rules overriding built-in mappings
- resources that are less specific than intended
- the active `VINCTOR_GRANT_REF`
- boundary identity and status

## Config Blocks Everything

Invalid config should fail closed.

Check:

- JSON syntax
- `version: 1`
- valid action verb
- non-empty pattern
- explicit resource without wildcard
- valid MCP tool name shape
- valid `inputField`

## MCP Rule Does Not Match

Check:

- Claude/Codex MCP tool names use `mcp__server__tool`
- Hermes MCP-style names may differ
- `inputField` only supports top-level fields
- unknown MCP servers are not automatically understood
- generated or discovered MCP mappings have been reviewed
