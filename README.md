# vinctor-core

Deterministic authorization core for mediated AI-agent actions.

> Status: early prototype. APIs and package boundaries may change.

## Local Prototype Quickstart

Start the local SQLite-backed prototype service:

```bash
.venv/bin/python -m vinctor_service.local_launcher \
  --db .vinctor-local.sqlite \
  --boundary-name claude-code-local
```

The launcher prints copy-pasteable exports:

```bash
export VINCTOR_ENDPOINT="http://127.0.0.1:<port>"
export VINCTOR_AGENT_KEY="aak_..."
export VINCTOR_GRANT_REF="grt_..."
export VINCTOR_WORKSPACE_KEY="wsk_..."
export VINCTOR_BOUNDARY_ID="bnd_..."
```

Keep the raw keys outside the repository. SQLite stores only key hashes and
metadata, not raw workspace or agent keys.

Copy these exports into the shell or process that will call the boundary while
the launcher keeps running.

Use the exports from a boundary caller:

```bash
curl -sS "$VINCTOR_ENDPOINT/v1/enforce" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $VINCTOR_AGENT_KEY" \
  -H "X-Vinctor-Boundary-Id: $VINCTOR_BOUNDARY_ID" \
  -d "{\"grant_ref\":\"$VINCTOR_GRANT_REF\",\"action\":\"write\",\"resource\":\"repo/feature/readme\"}"
```

The `/v1/enforce` body is intentionally strict: `grant_ref`, `action`, and
`resource`. Boundary context belongs in headers.

Restart with explicit keys:

```bash
.venv/bin/python -m vinctor_service.local_launcher \
  --db .vinctor-local.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-name claude-code-local
```

## Purpose

`vinctor-core` starts with the core authorization logic used to decide whether a
mediated AI-agent action should be permitted under a scoped grant.

This repository starts with the deterministic authorization core and now also
contains a thin `vinctor_service` application layer. Service-layer packages must
remain layered above the core. The core focuses on deterministic decision
behavior that can be tested, reviewed, and reused by service layers and runtime
boundary adapters.

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
- service-issued scoped grant lifecycle helpers
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
`_`, and `-`, with at least two segments such as `repo/feature`.

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

Disabled boundaries may be reactivated with `enable_boundary`, which preserves
the boundary identity and updates `updated_at`.

## Relationship to the Authorization Service

The `vinctor_service` package composes this core with service-shaped application
requests. Future service slices may add concerns such as HTTP APIs, caller
authentication, workspace and agent identity, durable audit storage, and service
availability. The current local service layer includes a first grant issuance
lifecycle for service-issued scoped grants.

Layering rule:

- `vinctor_core` must not import `vinctor_service`.
- `vinctor_service` may import `vinctor_core`.
- `vinctor_core` remains DB/HTTP/runtime-agnostic.
- `vinctor_service` owns HTTP APIs, auth headers, persistence, and
  workspace/agent/grant/boundary/audit storage.

This core should remain usable without a running HTTP service. The service
layer may call this core to evaluate decisions and then persist the resulting
audit record.

## Service Application Boundary

This repository includes `vinctor_service` as the first service-layer package.
It is intentionally thin: it maps service-shaped application requests onto
`vinctor_core` policy evaluation and maps the result back to a service-shaped
response.

`authorize_action` accepts:

- an `AuthorizationRequest`
- an explicit tuple of already-loaded `Grant` candidates
- the current time
- an optional boundary registry

`enforce_v1_contract` accepts:

- a `V1EnforceRequest`
- a `GrantRepository` for `grant_ref` lookup
- the current time
- an `AuditWriter`
- an optional boundary registry

It preserves v1 pre-audit failures and audit-before-decision behavior without
implementing HTTP routing, auth headers, durable grant storage, durable audit
persistence, hosted service behavior, or runtime adapter hooks. Those remain
future service-layer responsibilities.

Grant issuance is a separate service-layer decision from enforce-time
authorization. `GrantIssueRequest` and `GrantIssueResult` model workspace/admin
grant issuance. Execution agents consume issued `grant_ref` values; they do not
mint authority for themselves.

Agent issuable scope bounds are issuance constraints, not agent permissions.
Before a grant is issued, the service checks that every requested scope is
within the target agent's configured issuable scope bounds. For example,
`execute:ci/test` may be issued when the target agent's bounds include
`execute:ci/test`; `execute:deploy/production` is rejected when it is outside
those bounds.

`handle_v1_grants_http` maps workspace-key-protected grant lifecycle requests
into service-layer helpers:

- `POST /v1/grants` issues a grant for a target `agent_id`, requested `scopes`,
  and `ttl_seconds`.
- `GET /v1/grants/{grant_ref}` looks up a workspace-local grant.
- `POST /v1/grants/{grant_ref}/revoke` revokes a workspace-local grant.

These routes use `X-Workspace-Key`, not `X-Agent-Key`. Hooks remain
enforce-only and continue to call `POST /v1/enforce` with an already-issued
`grant_ref`.

The current service package exists to make the layering concrete:
`vinctor_service` imports `vinctor_core`, and `vinctor_core` does not import
`vinctor_service`.

`InMemoryV1Service` composes the in-memory grant repository, audit writer,
optional boundary registry, and v1 enforce adapter for integration tests and
local demos. It is not a durable service implementation.

`SQLiteGrantRepository` and `SQLiteAuditWriter` provide local SQLite-backed
implementations of the service-layer grant lookup and audit write boundaries.
`SQLiteBoundaryRegistry` provides local SQLite-backed boundary registration and
lookup for the existing boundary-aware enforce path. These helpers do not add
HTTP routing or hosted behavior.

`SQLiteV1Service` composes the SQLite grant repository, audit writer, boundary
registry, and v1 enforce adapter for local in-process integration tests and
demos. It exposes small helpers for grant issuance, grant lookup, grant
revocation, agent issuable scope bounds, boundary management, and audit event
lookup. It is not an HTTP service.

`handle_v1_enforce_http` maps a v1-shaped HTTP request into the service layer:
it validates `X-Agent-Key`, keeps the enforce body strict
(`grant_ref`/`action`/`resource`), and accepts optional boundary identity from
the `X-Vinctor-Boundary-Id` header. It is a contract adapter, not a server.

`handle_v1_boundaries_http` maps workspace-key-protected boundary registry
requests into service-layer boundary helpers. It supports `POST /v1/boundaries`,
`GET /v1/boundaries`, `GET /v1/boundaries/{boundary_id}`,
`POST /v1/boundaries/{boundary_id}/disable`, and
`POST /v1/boundaries/{boundary_id}/enable` for local contract tests. It does
not add delete behavior or approval workflows. `X-Workspace-Key` carries the
workspace-scoped local/admin token.

`create_v1_http_server` provides a small stdlib local HTTP wrapper for
`POST /v1/enforce`, `POST /v1/grants`, grant lookup/revocation, and boundary
registry demos and integration tests. It delegates request handling to the HTTP
contract adapters; it is not a hosted service or production HTTP server.

`python -m vinctor_service.local_launcher` starts a local SQLite-backed
prototype service and prints copy-pasteable exports:

```bash
.venv/bin/python -m vinctor_service.local_launcher \
  --db .vinctor-local.sqlite \
  --boundary-name claude-code-local
```

The launcher prints:

```bash
export VINCTOR_ENDPOINT="http://127.0.0.1:<port>"
export VINCTOR_AGENT_KEY="aak_..."
export VINCTOR_GRANT_REF="grt_..."
export VINCTOR_WORKSPACE_KEY="wsk_..."
export VINCTOR_BOUNDARY_ID="bnd_..."
```

`VINCTOR_BOUNDARY_ID` is optional and should be sent as the
`X-Vinctor-Boundary-Id` header when a local runtime boundary wants boundary
context included in enforce/audit behavior.

Local launcher keys are also written to SQLite as durable key records. The
service stores only a SHA-256 key digest plus metadata, never the raw key.
Workspace/admin keys use the `wsk_` prefix. Agent enforce keys use the `aak_`
prefix. If a raw key is lost, create or provide a new key rather than expecting
SQLite to recover the original secret.

Generated raw keys are explicit operator-managed secrets for now. The launcher
does not write them to SQLite, a local config file, or an OS keychain. After the
first run, reuse copied keys by passing them back explicitly:

```bash
.venv/bin/python -m vinctor_service.local_launcher \
  --db .vinctor-local.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-name claude-code-local
```

Re-running without `--workspace-key` and `--agent-key` may create additional
active local key records. Unknown or revoked keys continue to authenticate as a
generic `401 authentication_required`.

The bootstrap flow is covered by:

```bash
.venv/bin/python demo/local_service_bootstrap_demo.py
```

The grant lifecycle flow is covered by:

```bash
.venv/bin/python demo/grant_lifecycle_demo.py
```

This slice supports service-issued scoped, time-bounded, revocable grants. It
does not claim single-use JIT tokens, full JIT orchestration, least-privilege
orchestration, credential shielding, human approval workflow, or complete
enforcement isolation.

See `docs/decisions/0003-grant-lifecycle-jit-semantics.md` for the grant
lifecycle terminology: in Vinctor, JIT means issuance timing plus scoped,
time-bounded authority, not immediate one-shot expiration.

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
.venv/bin/python demo/in_memory_v1_service_demo.py
.venv/bin/python demo/sqlite_grant_audit_demo.py
.venv/bin/python demo/sqlite_boundary_registry_demo.py
.venv/bin/python demo/sqlite_v1_service_demo.py
.venv/bin/python demo/v1_http_contract_demo.py
.venv/bin/python demo/local_v1_http_service_demo.py
.venv/bin/python demo/boundary_admin_http_demo.py
.venv/bin/python demo/local_service_launch_helper_demo.py
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
- `src/vinctor_core/` - core authorization logic
- `src/vinctor_service/` - service-layer application helpers
- `tests/` - behavior-defining tests

## Status

Early prototype. Use for review and experimentation, not production-ready
authorization infrastructure.

The package boundaries, naming, and API surface may change.
