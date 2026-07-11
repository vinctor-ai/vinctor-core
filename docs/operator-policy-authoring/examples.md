# Operator Policy Examples

These examples show how hook mapping rules and service-issued grant scopes work
together.

The rule is simple: the mapped action/resource pair and the grant scope must
match.

## Documentation Task

Goal: allow repository reading, documentation edits, tests, and builds. Do not
allow secrets, release, or deploy.

Grant scopes:

```text
read:repo/*
write:repo/docs/*
execute:ci/test
execute:shell/build
```

Example mappings:

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "Bash",
      "matchType": "prefix",
      "pattern": "npm test",
      "action": "execute",
      "resource": "ci/test"
    },
    {
      "tool": "Bash",
      "matchType": "prefix",
      "pattern": "npm run build",
      "action": "execute",
      "resource": "shell/build"
    }
  ]
}
```

Expected behavior:

- `execute:ci/test` is permitted when the active grant includes it.
- `write:repo/docs/*` is permitted for mapped docs writes.
- secret reads deny when mapped to a secret resource not present in the grant.
- release and deploy actions deny unless explicitly included in the grant.

## Secrets

Goal: make secret access explicit.

Example resources:

```text
secret/env
secret/aws
secret/gcp
secret/azure
secret/package-registry
secret/kube
secret/app
```

Grant without secret access:

```text
read:repo/*
write:repo/docs/*
execute:ci/test
```

Grant with explicit environment-secret read:

```text
read:secret/env
read:repo/*
execute:ci/test
```

Use stable labels such as `secret/env`, not raw secret values or credential file
contents.

## Protected Files

Goal: require explicit authority for files that affect CI, packaging,
containers, infrastructure, or deployment.

Example grant scopes:

```text
write:repo/.github/workflows/*
write:repo/package.json
write:repo/Dockerfile
write:repo/infra/*
```

Example Codex `apply_patch` mapping for a project-specific protected file:

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "apply_patch",
      "matchType": "glob",
      "pattern": "**/release-plan.yaml",
      "action": "write",
      "resource": "repo/release-plan.yaml"
    }
  ]
}
```

## Release / Publish

Goal: make release authority explicit and absent by default.

Example mapping:

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "Bash",
      "matchType": "prefix",
      "pattern": "npm publish",
      "action": "execute",
      "resource": "release/npm"
    }
  ]
}
```

Matching grant scope:

```text
execute:release/npm
```

Current repository defaults may vary. Operators should treat action/resource
pairs as exact authorization identifiers and ensure grant scopes match the
configured runtime mappings.

## Staging vs Production Deploy

Goal: separate staging from production.

Example mappings:

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "Bash",
      "matchType": "prefix",
      "pattern": "make deploy-staging",
      "action": "execute",
      "resource": "deploy/staging"
    },
    {
      "tool": "Bash",
      "matchType": "prefix",
      "pattern": "make deploy-production",
      "action": "execute",
      "resource": "deploy/production"
    }
  ]
}
```

Staging grant:

```text
execute:deploy/staging
```

Production grant:

```text
execute:deploy/production
```

## WebFetch

Goal: treat selected outbound network destinations as authorization-relevant.

WebFetch mappings match hosts, not full URLs.

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "WebFetch",
      "matchType": "glob",
      "pattern": "*.internal.example.com",
      "action": "send",
      "resource": "net/internal/example.com"
    }
  ]
}
```

Grant scope:

```text
send:net/internal/example.com
```

Avoid putting full URLs, paths, query strings, or credentials into resources.

## WebSearch

WebSearch is a supported configurable tool surface. No built-in WebSearch mapping
ships by default.

Operators may add explicit mappings if they want selected WebSearch calls to
enter Vinctor authorization checks. Otherwise, WebSearch remains unmapped and
defers to runtime behavior where supported.

## MCP Filesystem

Goal: map filesystem MCP operations to repository or secret resources.

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "mcp__filesystem__read_file",
      "inputField": "path",
      "matchType": "glob",
      "pattern": "**/secrets.yaml",
      "action": "read",
      "resource": "secret/app"
    }
  ]
}
```

Grant with app-secret read:

```text
read:secret/app
```

If `inputField` is missing, non-string, or empty, the rule does not match. That
is not a deny by itself.

## MCP GitHub

Goal: separate read-only GitHub access from write or execute actions.

Example mapping:

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "mcp__github__merge_pull_request",
      "matchType": "exact",
      "pattern": "mcp__github__merge_pull_request",
      "action": "execute",
      "resource": "github/acme/api/pr"
    }
  ]
}
```

Example grant scopes:

```text
read:github/acme/api/issue
write:github/acme/api/issue
execute:github/acme/api/pr
```

Do not assume every MCP server has built-in mappings. Unknown MCP tools should
remain unmapped until reviewed or explicitly configured.

## Hermes MCP-Style Tools

Hermes may expose MCP-style dynamic tool names. Operators should review the
actual runtime tool name and map it explicitly when needed.

Example:

```json
{
  "version": 1,
  "rules": [
    {
      "tool": "mcp_internal_release_promote",
      "matchType": "exact",
      "pattern": "mcp_internal_release_promote",
      "action": "execute",
      "resource": "release/internal"
    }
  ]
}
```

Matching grant scope:

```text
execute:release/internal
```

## Future Direction: Memory / Context Retrieval

These are conceptual namespace examples for future memory/context boundaries:

```text
read:memory/project
read:session/search
write:memory/project
delete:memory/project
```

Do not treat these examples as a claim that a complete memory/context boundary
already exists across runtimes.
