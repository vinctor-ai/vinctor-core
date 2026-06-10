# vinctor-core

Deterministic authorization core for mediated AI-agent actions.

> Status: early prototype. APIs and package boundaries may change.

## Purpose

`vinctor-core` starts with the core authorization logic used to decide whether a
mediated AI-agent action should be permitted under a scoped grant.

This repository starts with the deterministic authorization core. Service-layer
packages may live here as the implementation matures, but must remain layered
above the core. The core focuses on deterministic decision behavior that can be
tested, reviewed, and reused by service layers and runtime boundary adapters.

Vinctor is the current working name and may change later.

## Core Question

This core answers one narrow question:

> Given an active grant, an action, a resource, and relevant authorization
> state, should this action be permitted?

The answer is a decision such as `permit` or `deny`. Service layers may
represent infrastructure failures as fail-closed outcomes outside this core.
The caller is responsible for enforcing the decision before tool execution.

## What This Core Owns

This repository is responsible for:

- grant and scope data models
- action/resource matching semantics
- permit/deny decision logic
- revoked or expired grant state checks
- boundary registry models
- deterministic reason codes
- audit event construction semantics
- tests that define expected authorization behavior

The goal is to keep the core small, explicit, and reviewable.

## What This Core Does Not Own

This repository does not implement:

- Claude Code, Codex, Hermes, LangGraph, or MCP hooks
- runtime adapter installation
- tool execution
- raw tool interception
- sandboxing or OS/process isolation
- provider credential management
- prompt/content safety
- approval workflows
- UI or operator console behavior
- hosted production service behavior

It only models authorization decisions for inputs explicitly passed to it.

## Decision Model

At minimum, a decision is based on:

- grant state
- requested action
- target resource
- request and grant scope validity
- scope matching
- revocation or expiration state
- optional boundary identity and status

The core should not infer intent from prompts or model output. Runtime adapters
are responsible for translating tool calls into action/resource pairs before
invoking the core.

## Scope Validation

Scopes use:

```text
action:resource
```

Valid action verbs are `read`, `write`, `execute`, `deploy`, `delete`, and
`send`. Resources are slash-separated segments using letters, numbers, `.`,
`_`, and `-`.

Grant scopes may use one terminal resource wildcard such as
`write:repo/feature/*`. Requested action/resource pairs must be concrete and
cannot contain wildcards.

Malformed requested actions return `invalid_action`. Malformed requested
resources return `invalid_resource`. Malformed grant scopes return
`invalid_grant_scope`.

## Policy Evaluation

`evaluate_policy` evaluates an explicit tuple of already-issued grants for one
workspace, agent, action, and resource. It does not load grants, persist
decisions, or own workspace storage.

Policy evaluation is deterministic:

- grants for other workspaces or agents are ignored
- grants are evaluated in the input order provided by the caller
- the first permitting grant returns `permit`
- if no candidate grant permits the request, the result is `deny` with
  `no_applicable_grant`

The service layer remains responsible for selecting which grants to pass into
the core.

## Relationship to Runtime Boundaries

Runtime boundaries are configured points where a runtime presents a proposed
tool call before execution.

Examples include Claude Code `PreToolUse` hooks, Codex hooks, Hermes adapter
dispatch, LangGraph tool wrappers, MCP tool boundaries, and memory/context
retrieval boundaries.

Those boundaries are responsible for:

- receiving runtime-specific tool events
- mapping tool input to action/resource
- calling the authorization service or core
- applying permit/deny before execution
- keeping runtime-specific output free of secrets and raw tool input

This core does not know Claude Code, Codex, Hermes, LangGraph, or MCP-specific
event formats.

Boundary names are unique within a workspace. Different workspaces may reuse
the same boundary name.

## Relationship to the Authorization Service

The authorization service, whether it lives in this repository later as
`vinctor_service` or in a separate package, composes this core with service
concerns such as HTTP APIs, caller authentication, workspace and agent identity,
durable grant storage, durable audit storage, revocation endpoints, and service
availability.

Layering rule:

- `vinctor_core` must not import `vinctor_service`.
- `vinctor_service` may import `vinctor_core`.
- `vinctor_core` remains DB/HTTP/runtime-agnostic.
- `vinctor_service` owns HTTP APIs, auth headers, persistence, and
  workspace/agent/grant/boundary/audit storage.

This core should remain usable without a running HTTP service. The service
layer may call this core to evaluate decisions and then persist the resulting
audit record.

## Audit Semantics

The core may construct audit event data, but it does not own durable audit
persistence.

Durable audit storage belongs to the service layer.

Audit-related behavior should remain deterministic and testable. If a decision
changes, the corresponding audit event semantics should be updated with tests.

Audit records must not include raw tool input, raw command text, prompts, or
model-facing reason strings.

## Development Principles

This repo should stay small and deterministic.

Expected workflow:

1. Define behavior with tests.
2. Implement the minimum logic needed to pass.
3. Simplify the code after tests pass.
4. Keep public behavior documented.
5. Avoid adding runtime-specific behavior to the core.

Tests are part of the public contract. If behavior changes, tests and
documentation should change together.

## Testing

Python 3.11 or newer is required.

```bash
/opt/homebrew/bin/python3.11 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/python demo/boundary_registry_core_e2e.py
.venv/bin/ruff check .
.venv/bin/python -m build
git diff --check
```

## Repository Guide

- `README.md` - public overview of this core package
- `AGENTS.md` - instructions for AI coding agents
- `.github/workflows/ci.yml` - public CI for tests, demo, lint, and whitespace
- `docs/next-actions.md` - current work state and next tasks
- `docs/decisions/` - durable design decisions when needed
- `src/` - core authorization logic
- `tests/` - behavior-defining tests

## Status

Early prototype. Use for review and experimentation, not production-ready
authorization infrastructure.

The package boundaries, naming, and API surface may change.
