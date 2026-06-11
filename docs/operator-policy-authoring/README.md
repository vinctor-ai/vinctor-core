# Operator Policy Authoring Guide

This guide explains how operators author Vinctor policy inputs for configured
runtime boundaries.

Vinctor runtime boundaries translate selected runtime tool calls into concrete
`(action, resource)` checks and ask the Vinctor service for a permit/deny
decision. Hooks and plugins do not issue grants.

Current runtime boundaries include:

- Claude Code hook
- Codex CLI hook
- Hermes plugin

These boundaries consume:

```text
VINCTOR_ENDPOINT
VINCTOR_AGENT_KEY
VINCTOR_GRANT_REF
```

## Core Rule

Hook config maps. Service-issued scoped grants authorize.

A hook rule does not grant permission. It decides which authorization check the
boundary sends to the service. The service permits only when the active grant
contains a matching scope.

## Policy Inputs

| Input | Purpose | Does not |
| --- | --- | --- |
| Hook mapping rules | Translate runtime-specific calls to `(action, resource)` | Grant access |
| Service-issued scoped grants | Define permitted scopes for a grant reference | Discover tool calls |
| Action/resource taxonomy | Give stable names to checks | Enforce by itself |
| Runtime boundary behavior | Apply mapped permit/deny before execution | Cover every runtime path universally |

## Boundary Outcomes

| Result | Meaning |
| --- | --- |
| Permit | Mapped call was allowed by the service grant |
| Deny | Mapped call was rejected by service/core, config, auth, or fail-closed behavior |
| Unmapped / abstain / ask | Boundary did not produce an authorization check; runtime fallback applies where supported |

Unmapped is not the same as permitted. It means Vinctor did not decide.

## Hook Config vs Grant Scope

Put runtime-specific matching in hook config:

```json
{
  "tool": "Bash",
  "matchType": "prefix",
  "pattern": "npm publish",
  "action": "execute",
  "resource": "release/npm"
}
```

Put authorization intent in grant scopes:

```text
execute:release/npm
execute:ci/test
write:repo/docs/*
send:net/external/docs.example.com
```

Action/resource pairs are exact authorization identifiers. Grant scopes must
match the configured runtime mappings.

## Scope Syntax

Valid actions are:

```text
read
write
execute
deploy
delete
send
```

Requested runtime checks must use concrete resources:

```text
write:repo/docs/README.md
send:net/external/example.com
```

Grant scopes may use one terminal resource wildcard:

```text
write:repo/docs/*
read:github/acme/api/*
```

Do not use wildcards in hook config resources.

## What To Map

Map calls that are sensitive, consequential, or important to audit:

- secret and credential reads
- protected file writes
- release and publish commands
- deploy commands
- destructive git, Docker, filesystem, or infrastructure operations
- outbound network calls where destination matters
- MCP filesystem, GitHub, Slack, and internal-system tools
- future memory/context retrieval boundaries when they exist and handle sensitive context

Leave calls unmapped when the runtime's native approval behavior is preferred,
the tool shape is unstable, or an MCP tool has not been reviewed.

## Boundary-Specific Notes

Claude Code returns `ask` for unmapped calls.

Codex may abstain and let Codex's native approval flow continue. Codex hook event
coverage is runtime-version dependent; a mapping matters only when Codex emits
the relevant hook event.

Hermes has a broader plugin surface, including terminal, file, process,
web/browser, messaging, and MCP-style tools. Operators should review generated or
discovered tool mappings before relying on them at runtime.

## Resource Discipline

Do not put raw commands, secrets, prompts, query strings, tokens, or credentialed
URLs into resources. Resources should be stable authorization labels.

Good examples:

```text
secret/env
secret/aws
repo/docs/*
ci/test
release/npm
deploy/staging
net/external/example.com
github/acme/api/pr
message/slack/channel
```

Avoid examples:

```text
AWS_SECRET_ACCESS_KEY=...
https://user:token@example.com/path
npm publish --token ...
```

## Claim Discipline

This guide may say Vinctor supports operator-authored policy inputs, hook mapping
rules, service-issued scoped grants, configured runtime boundaries, and runtime
authorization checks.

This guide should stay focused on mapping rules, grant scopes, and configured
runtime-boundary behavior. Keep broader product, service, and workflow claims in
their own documents.

## Taxonomy Note

Action/resource taxonomy continues to evolve. Operators should treat currently
configured action/resource pairs as the source of truth until a canonical
cross-boundary taxonomy is finalized.

## Related Guides

- `examples.md` shows mapping and grant scope examples.
- `approval-mode-examples.md` shows when to use auto-approval, human/operator
  review, disabled rules, or rejection.
- `troubleshooting.md` lists common policy and mapping failures.
