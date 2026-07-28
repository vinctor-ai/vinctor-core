# vinctor-core

Deterministic authorization core for mediated AI-agent actions. The core answers
one question — *should this agent action be allowed under its grant?* — and
returns a reviewable `permit`/`deny`, staying independent of any runtime,
database, or HTTP stack.

> Status: early prototype. APIs and package boundaries may change.

![Vinctor — the control point that permits or denies covered AI-agent actions by context](https://raw.githubusercontent.com/vinctor-ai/vinctor-core/main/docs/assets/vinctor-hero.svg)

## Purpose

`vinctor-core` holds the authorization logic that decides whether a mediated
AI-agent action should be permitted under a scoped grant. The repository pairs
that deterministic core with a thin `vinctor_service` application layer, which
must stay layered above the core. The core focuses on deterministic decision
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

## See it

The clip below runs the real CLI. The agent holds a single grant —
`send:net/internal/*, deploy:env/staging/*` — and you watch the **same kind of action
get opposite verdicts depending on context**:

![Vinctor golden-path demo: the same action allowed or denied by context](https://raw.githubusercontent.com/vinctor-ai/vinctor-core/main/docs/assets/golden-path-demo.gif)

- `send` → `net/internal/orders-api` is **permitted** — an internal call the grant covers.
- `send` → `net/external/pastebin.com` is **denied** — the *same* `send` action, but an
  external destination (the exfiltration path) the grant never covered.
- `deploy` → `env/production/web` is **denied** — the grant covers
  `deploy:env/staging/*`, never production.

Nothing is on a denylist. Configured, mediated calls that reach a Vinctor boundary
are mapped to an `(action, resource)` pair and checked against the grant
**before execution**. Every verdict you receive has been recorded — if the durable
audit write fails, the call returns `503` and no decision at all, never an
unrecorded permit (see [No audit row, no decision](#no-audit-row-no-decision)).
The verdict lives in the authorization context (grant state, agent identity,
action, resource, evaluation time, and optional boundary), not in the command
string — which is exactly what a denylist cannot express.

Vinctor authorizes configured, mediated tool calls that reach its boundary; it is
not a sandbox. Adapter coverage varies by runtime, version, tool surface, and
mapping. To run this yourself, see [Install](#install) and the
[Local Prototype Quickstart](#local-prototype-quickstart).

## Install

Vinctor is a Python ≥ 3.11 package that installs two console commands —
`vinctor` (the operator/agent CLI) and `vinctor-mcp-server` (the read-only MCP
control plane). Install it as a standalone tool with
[pipx](https://pipx.pypa.io) (recommended for a CLI), or with `pip` into a
virtualenv — no `PYTHONPATH` or `python -m …` invocation needed:

```bash
# Standalone CLI (recommended), straight from PyPI:
pipx install vinctor-core
# include the MCP control plane:  pipx install "vinctor-core[mcp]"

# …no pipx on this machine? install into a virtualenv instead:
python3.11 -m venv .venv && .venv/bin/python -m pip install vinctor-core

vinctor --help
vinctor local start --db .vinctor-local.sqlite   # bootstrap a local service and print VINCTOR_* exports
```

(Working from a checkout instead? `pipx install .` / `pip install .` from the
repo root installs the same CLI.)

`--db` is required by `vinctor local start`; the snippet above writes the local
service state to `.vinctor-local.sqlite`.

### Docker

The released image runs as a non-root user and is pushed to GHCR. The package
is set to public visibility in GHCR (a registry-side setting this repo's
workflow does not control), so pulling needs no login:

```bash
docker pull ghcr.io/vinctor-ai/vinctor-core:0.6.0     # or :latest
docker run --rm ghcr.io/vinctor-ai/vinctor-core:0.6.0 vinctor --help
```

The image's default command is `vinctor service serve`, so running it with no
arguments starts the service — see
[Self-Hosting](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/deployment/self-hosting.md)
for the `compose.yaml` that gives it a persistent volume, and
[Operational Runbooks](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/deployment/operational-runbooks.md)
for TLS, backups and supervision.

Two things worth knowing before you pull:

- **`linux/amd64` only.** On arm64 (Apple Silicon, Graviton) Docker will fall
  back to emulation if it can, which is slow — or refuse. Install from PyPI
  there instead.
- **Supply-chain attestations are attached to the image**, not published to
  GitHub's attestation API — the image is built with buildx `provenance: true`
  and `sbom: true`, so `gh attestation verify` finds nothing and that is
  expected. Read them with `docker buildx imagetools inspect`, which resolves
  the OCI index and its attestation manifest.

The base `pip install vinctor-core` / `pipx install vinctor-core` ships the
`vinctor-mcp-server` command, but running it needs the `[mcp]` extra (the MCP
SDK). Install `pipx install "vinctor-core[mcp]"` (or
`pip install "vinctor-core[mcp]"`) to run it.
Without the extra it exits with a clean one-line error
(`error: MCP SDK is required to run vinctor-mcp-server. Install with
vinctor-core[mcp].`). The SDK check runs **before** configuration is validated,
so that is the message even with neither `VINCTOR_MCP_ENDPOINT` nor
`VINCTOR_MCP_WORKSPACE_KEY` set — the missing extra is never masked by an
env-var error. Note that `vinctor-mcp-server --help` exits `0` without the
extra, since argument parsing precedes startup; `--help` succeeding is not
evidence the server can run.

### What the base install gives you

**The base install is a complete, supported deployment.** SQLite is the default
backend and needs no extra: `vinctor service serve`, enforce, audit, and the
whole CLI work with nothing installed beyond `vinctor-core` itself. Every extra
is genuinely optional — Postgres (`[postgres]`), the MCP control plane
(`[mcp]`), and OIDC subject tokens (`[oidc]`) each buy one feature and nothing
else. Selecting a feature without its extra fails immediately and names the
extra to install; it never fails later or half-way through a request. Each
guard sits at startup, not on the request path: Postgres refuses at connect
(`vinctor-core[postgres]`), OIDC at verifier construction during service start
(`vinctor-core[oidc]`), and the MCP server before it reads its configuration
(`vinctor-core[mcp]`).

This is a tested configuration, not an assumed one. CI's `bare-install` job
installs the built wheel into a virtualenv with no extras and then runs the
console scripts, imports every module in the distribution, and runs the SQLite
service demo — so an optional dependency that leaks into a required import path
fails CI rather than reaching PyPI.

To **contribute** (editable install + dev tools + tests), see [Testing](#testing).

## Local Prototype Quickstart

With Vinctor installed (see [Install](#install)), run a complete service-style
demo:

```bash
vinctor demo service
```

(Working from a source checkout, `make demo` runs the same thing. The
`Makefile`, `demo/`, `docs/`, and `tools/` directories are **not** in the wheel,
so on a `pip`/`pipx` install `vinctor demo service` is the way in — everything
below uses only what the install ships.)

Then start the local SQLite-backed prototype service:

```bash
vinctor local start \
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
the launcher keeps running — every command below reads `VINCTOR_ENDPOINT` and
`VINCTOR_AGENT_KEY`/`VINCTOR_WORKSPACE_KEY` from the environment, and exits with
`error: agent key is required` in a shell that does not have them.

`vinctor local start` also sets `agent_local`'s **issuable scope bounds** — to
`write:repo/feature/*`, the same scope as the bootstrap grant it issues
(`local_launcher.py` sets the bounds and the grant from one value). Bounds are a
ceiling on future issuance, not a restriction on already-issued grants.

Agents can request grants, then operators decide them:

```bash
vinctor agent requests create \
  --scope "write:repo/feature/*" \
  --ttl 15m \
  --reason "edit the feature branch"

# No auto-approval rule exists yet, so `evaluate` leaves it pending:
#   pending request grq_... routing=manual_review_required reason=no_matching_rule
vinctor operator requests evaluate <request_id>

# A manual decision issues the grant:
vinctor operator requests approve <request_id>

vinctor agent requests status <request_id>
```

A request for a scope **outside** those bounds is still created, but can never
be granted — approval fails at issuance:

```text
$ vinctor agent requests create --scope execute:ci/test --ttl 15m --reason "run CI validation"
created request grq_... status=pending routing=manual_review_required scopes=execute:ci/test
$ vinctor operator requests approve grq_...
error: 403 scope_outside_issuable_bounds: scope_outside_issuable_bounds
```

Widen the ceiling first if that is what you want:

```bash
vinctor --db .vinctor-local.sqlite \
  operator bounds set agent_local \
  --scope "write:repo/feature/*" \
  --scope execute:ci/test
```

Bounds and auto-approval rules can also be applied as a file with `operator
policy apply` — see
[Operator policy authoring](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/operator-policy-authoring/policy-file.md)
and the
[example policies](https://github.com/vinctor-ai/vinctor-core/tree/main/docs/examples).
Those YAML files live in the repository, not in the wheel.

For a complete local service flow, see the
[demo service runbook](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/demo-service-runbook.md).

Run the service runtime without bootstrapping new keys:

```bash
vinctor service serve \
  --host 127.0.0.1 \
  --port 8765 \
  --db .vinctor/vinctor.sqlite \
  --mode self_hosted
```

This opens an existing SQLite-backed service state and exposes `/healthz` plus
the local v1 API. It does not print raw keys or create grants by itself. See
[Self-Hosting](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/deployment/self-hosting.md).

For repeatable demo policy templates, see
[docs/examples/policies/](https://github.com/vinctor-ai/vinctor-core/tree/main/docs/examples/policies).

For the machine-readable local API contract, see
[docs/openapi/v1.yaml](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/openapi/v1.yaml).

For the read-only MCP control-plane interface, see
[docs/mcp-server.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/mcp-server.md).

Hook/plugin repositories can use the deterministic mock `/v1/enforce` fixture
for integration smoke tests. It is a standalone script in the repository, not
part of the installed package, so fetch it from a checkout or from
[tools/mock_vinctor_service.py](https://github.com/vinctor-ai/vinctor-core/blob/main/tools/mock_vinctor_service.py).

First create a `mock-vinctor.json` config (schema in
[docs/testing/mock-vinctor-service.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/testing/mock-vinctor-service.md)),
then run it on a free port (8765 above is already used by `service serve`):

```bash
python tools/mock_vinctor_service.py --port 8799 --config mock-vinctor.json
```

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

An observe-mode boundary records mapped calls without requiring or applying a
grant:

```bash
curl -sS "$VINCTOR_ENDPOINT/v1/observe" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $VINCTOR_AGENT_KEY" \
  -H "X-Vinctor-Boundary-Id: $VINCTOR_BOUNDARY_ID" \
  -d '{"classification":"mapped","action":"write","resource":"repo/feature/readme"}'
```

Unmapped calls send only `{"classification":"unmapped"}`. A PEP that
fail-closed an unmapped call can add `"outcome":"blocked_unmapped"`; Vinctor
stores a coarse `action_blocked_unmapped` deny event without action or resource
details. The endpoint never accepts raw tool input or prompt content. Successful
mapped observations are stored as `action_observed` audit events and are
available to `operator policy infer`; inference remains propose-only and
exact-scope by default.
Use `operator policy infer --min-observations 2` (or a higher threshold) to
exclude one-off pairs before reviewing a proposal. Proposal entries distinguish
observed, enforced, and simulated evidence, and the document summarizes mapping
gaps and dry-run outcomes. Use `--generalize` over enforced evidence, not
observed-only evidence reported by an agent.

Before promoting a policy to enforcement, a boundary can calculate the same
decision without using it as a gate:

```bash
curl -sS "$VINCTOR_ENDPOINT/v1/simulate" \
  -H "Content-Type: application/json" \
  -H "X-Agent-Key: $VINCTOR_AGENT_KEY" \
  -H "X-Vinctor-Boundary-Id: $VINCTOR_BOUNDARY_ID" \
  -d "{\"grant_ref\":\"$VINCTOR_GRANT_REF\",\"action\":\"write\",\"resource\":\"repo/feature/readme\"}"
```

The response is `200` for both evaluated outcomes and reports
`would_decision: permit|deny`. It never authorizes or blocks the caller's tool
execution. Every successful calculation is stored as `action_would_permit` or
`action_would_deny`; invalid requests and unavailable storage fail explicitly.

For rolling this out end to end — observe → simulate → selective enforcement →
enforce, driven by the PEP's `VINCTOR_ENFORCEMENT_MODE` — see
[docs/deployment/gradual-rollout.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/deployment/gradual-rollout.md).

Restart with explicit keys:

```bash
vinctor local start \
  --db .vinctor-local.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-name claude-code-local
```

Write an explicit local env file when you choose to persist test/dev values:

```bash
vinctor \
  --endpoint "$VINCTOR_ENDPOINT" \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-id "$VINCTOR_BOUNDARY_ID" \
  local env --write-file .vinctor.env
```

`.vinctor.env` is ignored by git. Keep raw keys out of committed files.

## Decision Model

At minimum, a decision is based on:

- grant state
- requesting agent identity — a grant is reachable only by the agent it was
  issued to; another agent presenting the same `grant_ref` is refused without
  disclosing whether it exists
- requested action
- target resource
- request and grant scope validity
- scope matching
- revocation or expiration state, evaluated against the time of the request
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
`write:repo/feature/*`. A wildcard requires at least two concrete resource
segments before `/*`; `read:repo/*` is invalid. Requested action/resource pairs
must be concrete and cannot contain wildcards.

Malformed requested actions return `invalid_action`. Malformed requested
resources return `invalid_resource`. Malformed grant scopes return
`invalid_grant_scope`. These are the core-layer (`evaluate_policy` / `enforce`)
decision reasons; the v1 HTTP contract pre-validates malformed input and surfaces
it as `scope_invalid` (see [docs/api-contract.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/api-contract.md)).

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

### Disabling a boundary is not a kill switch

**Disabling a boundary stops nothing on its own.** The boundary reaches Vinctor
in the caller-controlled `X-Vinctor-Boundary-Id` header, so a call that simply
omits the header is evaluated as if no boundary were involved — the disabled
boundary is never consulted. Against a boundary in `mode: fail_closed,
status: disabled`, the *same* enforce call gives opposite answers:

```text
with    X-Vinctor-Boundary-Id  →  403  {"decision":"deny","error":"boundary_unavailable"}
without X-Vinctor-Boundary-Id  →  200  {"decision":"permit"}
```

This is not a bug in the boundary check: the boundary identifies *where* a call
was intercepted, and a caller that does not claim a boundary has not made a
false claim. But an operator who disables a boundary believing it is an
emergency stop has stopped nothing — the runtime only has to drop one header,
and a compromised or merely misconfigured PEP does exactly that.

**`require-boundary` is the control that makes the boundary mandatory.** With
it enabled, an enforce call with no boundary id is denied outright:

```bash
vinctor --db .vinctor-local.sqlite operator require-boundary enable agent_local
# require_boundary workspace=ws_local agent=agent_local value=True
```

```text
without X-Vinctor-Boundary-Id  →  403  {"decision":"deny","error":"boundary_required"}
```

Pass `--workspace` instead of an agent id to mandate it for every agent in the
workspace, and `operator require-boundary show` to read the current setting. The
setting is read per enforce call, so it takes effect on a running service with
no restart.

On a **new 0.6.0 database**, `require_boundary` defaults to `1` — on. Databases
created by an earlier release retain their existing schema default and stored
overrides, so an upgrade does not turn the mandate on behind the operator's
back. `operator require-boundary disable` remains the explicit escape hatch.
Requiring the boundary plus disabling it is what an emergency stop looks like:
the first makes the header mandatory, the second makes the named boundary fail
closed.

Two limits worth knowing before you rely on it:

- **It is settable only through `--db` today.** `operator require-boundary`
  opens the SQLite/Postgres database directly; there is no HTTP route and no
  MCP tool for it, and `--endpoint` is ignored. An operator without filesystem
  or database access to the deployment cannot turn it on. (`operator policy
  apply`, also `--db`-only, can enable it additively from a policy file.)
- **A fresh install denies every PEP that does not send the header.** Existing
  databases remain off until explicitly enabled. Before creating a new
  database, verify every adapter sends `X-Vinctor-Boundary-Id`; for local use,
  `vinctor local start` creates the default `claude-code-local` boundary and
  prints its `VINCTOR_BOUNDARY_ID` (use `--boundary-name` to override it).

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

Local operators can apply and export these bounds and auto-approval rules with
`vinctor operator policy apply/export` using the `policy.yaml` schema documented
in [docs/operator-policy-authoring/policy-file.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/operator-policy-authoring/policy-file.md).

`handle_v1_grants_http` maps workspace-key-protected grant lifecycle requests
into service-layer helpers:

- `POST /v1/grants` issues a grant for a target `agent_id`, requested `scopes`,
  and `ttl_seconds`.
- `GET /v1/grants/{grant_ref}` looks up a workspace-local grant.
- `POST /v1/grants/{grant_ref}/revoke` revokes a workspace-local grant.

These routes use `X-Workspace-Key`, not `X-Agent-Key`. Hooks remain
enforce-only and continue to call `POST /v1/enforce` with an already-issued
`grant_ref`.

Grant requests are separate from grant issuance. Execution agents may create a
pending request for scoped authority, but that request does not mint authority:

- `POST /v1/grant-requests` uses `X-Agent-Key` and creates a pending request
  for the authenticated agent.
- `GET /v1/grant-requests` and `GET /v1/grant-requests/{request_id}` use
  `X-Workspace-Key` for workspace/admin review.
- `POST /v1/grant-requests/{request_id}/approve` uses `X-Workspace-Key` and,
  on success, calls the existing service-issued grant path.
- `POST /v1/grant-requests/{request_id}/reject` uses `X-Workspace-Key` and
  closes the request without issuing a grant.

Approval remains mediated by a separate workspace/admin authority. The
execution agent that requested authority cannot approve its own request through
the agent-key route. This is an approval boundary, not a full human approval
workflow or automated policy engine.

Grant requests should be routed by workspace/admin authority or a future
orchestrator acting with that authority. Auto-approval is an opt-in path for
low-risk, repeatable, narrow requests with matching admin-defined rules. Higher
impact requests, such as production deploys, refunds, migrations,
customer-impacting operations, destructive actions, broad scopes, long TTLs, or
production secret access should remain pending for human/operator review or be
rejected by workspace/admin authority. See
[docs/decisions/0005-grant-request-routing-and-approval-modes.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/decisions/0005-grant-request-routing-and-approval-modes.md).

Auto-approval rules are workspace/admin-controlled service data. The
auto-approval path provides in-process helpers for admin-defined rules, a
dry-run evaluator, workspace-key-protected HTTP/admin contracts for rule
management, and a service path that can turn a matching pending request into a
service-issued grant:

- `AutoApprovalRule` defines the target agent, allowed scopes, maximum TTL,
  status, and admin metadata for a rule.
- `create_auto_approval_rule` stores an admin-defined rule.
- `evaluate_auto_approval` checks a pending grant request against active rules
  and returns `auto_approval_match`, `scope_outside_rule`, `ttl_exceeds_rule`,
  `no_matching_rule`, or `grant_request_not_pending`.
- `auto_approve_grant_request` evaluates a pending grant request and, when a
  rule matches, reuses the existing grant request approval and service-issued
  grant lifecycle.
- `handle_v1_auto_approval_rules_http` maps admin rule management requests:
  `POST /v1/auto-approval-rules`, `GET /v1/auto-approval-rules`, and
  `POST /v1/auto-approval-rules/{rule_id}/disable`.
- `POST /v1/grant-requests/{request_id}/auto-approve` maps workspace-key
  protected auto-approval attempts into that service path.

These auto-approval rule management routes use `X-Workspace-Key`, not
`X-Agent-Key`. Execution agents can request authority, but they cannot create,
list, disable, or invoke the rules that may later approve those requests.

Non-matching auto-approval attempts leave the grant request pending and do not
issue a grant. Matching auto-approval attempts still use workspace/admin
authority, still pass through agent issuable scope bounds, and write
`grant_issued` plus `grant_request_auto_approved` audit events.

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
`POST /v1/enforce`, `POST /v1/grants`, grant lookup/revocation, boundary
registry routes, grant request routes, and auto-approval rule management routes
for demos and integration tests. It delegates request handling to the HTTP
contract adapters; it is not a hosted service or production HTTP server.

`vinctor local start` starts a local SQLite-backed prototype service and prints
copy-pasteable exports:

```bash
vinctor local start \
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

`VINCTOR_BOUNDARY_ID` must be sent as the `X-Vinctor-Boundary-Id` header on a
fresh 0.6.0 database. Existing databases retain their earlier mandate default;
an operator can also explicitly disable it with
`operator require-boundary disable`.

Local launcher keys are also written to SQLite as durable key records. The
service stores only a SHA-256 key digest plus metadata, never the raw key.
Workspace/admin keys use the `wsk_` prefix. Agent enforce keys use the `aak_`
prefix. If a raw key is lost, create or provide a new key rather than expecting
SQLite to recover the original secret.

Generated raw keys are explicit operator-managed secrets for now. The launcher
does not write them to SQLite, a local config file, or an OS keychain. After the
first run, reuse copied keys by passing them back explicitly:

```bash
vinctor local start \
  --db .vinctor-local.sqlite \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-name claude-code-local
```

Re-running without `--workspace-key` and `--agent-key` may create additional
active local key records. Unknown or revoked keys continue to authenticate as a
generic `401 authentication_required`.

For repeat demos, `vinctor local env` formats the values you already have as a
copy-pasteable export block. It does not recover lost raw keys from SQLite:

```bash
vinctor \
  --endpoint "$VINCTOR_ENDPOINT" \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  --grant-ref "$VINCTOR_GRANT_REF" \
  --boundary-id "$VINCTOR_BOUNDARY_ID" \
  local env
```

For local demos, `vinctor` provides a thin operator/agent helper around the local
HTTP service and SQLite database. It is intended for prototype operation, not as
a hosted admin console:

```bash
vinctor \
  --endpoint "$VINCTOR_ENDPOINT" \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  operator requests list

vinctor \
  --endpoint "$VINCTOR_ENDPOINT" \
  --agent-key "$VINCTOR_AGENT_KEY" \
  agent requests create \
  --scope write:repo/feature/readme \
  --ttl 30m \
  --reason "edit the feature readme"

vinctor \
  --endpoint "$VINCTOR_ENDPOINT" \
  --workspace-key "$VINCTOR_WORKSPACE_KEY" \
  operator requests evaluate grq_...

vinctor \
  --db .vinctor-local.sqlite \
  operator audit list --limit 10
```

Use `operator rules create/list/disable` for rule management, `operator bounds
set/show` for local agent issuable scope bounds, and `agent enforce` to send a
local permit/deny check without hand-writing curl. The older
`python -m vinctor_service.local_admin` and
`python -m vinctor_service.local_launcher` module calls remain developer
fallbacks.

A **PEP** (resource server) authenticates to `POST /v1/enforce/delegated` with
an `X-PEP-Key` header. Mint that key with:

```bash
vinctor --db .vinctor-local.sqlite \
  operator keys create pep --pep-id pep_git_host
```

The raw key is printed once and cannot be recovered afterwards — SQLite stores
only its digest. `create` leaves existing PEP keys active, so standing up a
second PEP does not lock out the first; use `operator keys rotate pep --pep-id
<id>` when you specifically want the previous key revoked. Like every other
`operator keys` subcommand it operates on `--db` (or `VINCTOR_DB`) directly, not
against `--endpoint`.

Bootstrap, grant lifecycle, grant requests, auto-approval, manual review, and
the git-repo boundary scenario each have a runnable script. They live in the
repository's
[`demo/`](https://github.com/vinctor-ai/vinctor-core/tree/main/demo) directory,
which is **not** part of the wheel — run them from a source checkout, not from a
`pip`/`pipx` install:

```bash
.venv/bin/python demo/local_service_bootstrap_demo.py      # bootstrap
.venv/bin/python demo/grant_lifecycle_demo.py              # grant lifecycle
.venv/bin/python demo/grant_request_lifecycle_demo.py      # grant request lifecycle
.venv/bin/python demo/auto_approval_dry_run_demo.py        # auto-approval dry run
.venv/bin/python demo/auto_approval_http_admin_demo.py     # auto-approval rule admin over HTTP
.venv/bin/python demo/auto_approval_service_path_demo.py   # auto-approval service path
.venv/bin/python demo/local_operator_flow_demo.py          # local operator flow
.venv/bin/python demo/manual_review_required_demo.py       # manual review required
.venv/bin/python demo/git_repo_boundary_demo.py            # git repo boundary scenario
```

A single local smoke check ships with the package itself:

```bash
vinctor --json demo check
```

This slice supports service-issued scoped, time-bounded, revocable grants. It
does not claim single-use JIT tokens, full JIT orchestration, least-privilege
orchestration, credential shielding, human approval workflow, or complete
enforcement isolation.

See [docs/decisions/0003-grant-lifecycle-jit-semantics.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/decisions/0003-grant-lifecycle-jit-semantics.md) for the grant
lifecycle terminology: in Vinctor, JIT means issuance timing plus scoped,
time-bounded authority, not immediate one-shot expiration.

## Audit Semantics

The core may construct audit event data, but it does not own durable audit
persistence.

Durable audit storage belongs to the service layer.

### Postgres service backend

Install the optional Postgres backend with `pip install "vinctor-core[postgres]"`.

**The Postgres backend requires a bounded query cancellation** —
`Connection.cancel_safe()`, which needs **psycopg 3.2 or newer** *and* **libpq
17 or newer** — and refuses to start without it, naming the detected versions.
Without it a readiness probe that wedges can never be reclaimed and `/readyz`
stays unavailable after the database recovers. Installing
`vinctor-core[postgres]` normally satisfies both, but note that
`psycopg[binary]>=3.2` pins the *driver*, not the libpq it bundles, and
`pyproject.toml` cannot express a libpq floor at all — the startup check is what
enforces it. SQLite is unaffected.
`PostgresV1Service` provides the full durable HTTP control plane, including
grants, requests, boundaries, settings, local key hashes, subject tokens,
cross-instance PoP replay prevention, and hash-chained audit storage. Schema
creation is explicit through `init_postgres_schema(connection)`; concurrent
writers use Postgres constraints and advisory locks so multiple service
instances cannot fork the audit chain or accept the same PoP nonce twice.

Select it for `vinctor service serve` with `VINCTOR_STORAGE_BACKEND=postgres`
and `VINCTOR_POSTGRES_DSN`. SQLite remains the default. See
[docs/deployment/postgres.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/deployment/postgres.md) for bootstrap, readiness, backup, and test details.

Selecting Postgres without the extra fails at startup with a single line —
``error: Postgres support requires `pip install vinctor-core[postgres]` `` —
and exit code 5. It does not silently fall back to SQLite, and it echoes back
neither the DSN nor a traceback.

Audit-related behavior should remain deterministic and testable. If a decision
changes, the corresponding audit event semantics should be updated with tests.

Audit records must not include raw tool input, raw command text, prompts, or
model-facing reason strings.

### Tamper-evidence

Every audit row is hash-chained (`seq` + `prev_hash` + `row_hash =
sha256(seq \n event_json \n prev_hash)`). `vinctor operator audit verify` walks
the chain and reports the first modification, deletion, reorder, or
filter-column edit. `vinctor operator audit head` prints the chain tip.

The chain makes tampering **detectable**; how far it is **preventable** depends
on where you anchor the head (`VINCTOR_AUDIT_ANCHOR=file:/secured/path` or
`stdout`):

| Anchor | Guarantee vs. an attacker who controls the DB file |
| --- | --- |
| none | tamper-evident (a surgical edit breaks the chain; a full-tail recompute is undetectable without a reference) |
| same-host, same-privilege file | still only evident — the attacker rewrites the anchor too |
| OS-separated local (append-only / root-owned / WORM) | resistant up to defeating that separation |
| independent external sink | effectively resistant; only the un-anchored tail is exposed |

Anchoring is off by default. Set `VINCTOR_AUDIT_SINK_REQUIRED=true` for a
production profile that refuses startup unless at least one valid
`VINCTOR_AUDIT_ANCHOR` or `VINCTOR_AUDIT_EXPORT` sink is configured. Explicit
unknown sink specs, empty `file:` paths, and file destinations that cannot be
opened for append also refuse startup. File destinations are opened without
writing audit content.

After startup, anchoring and export remain fail-open: a sink that later becomes
unavailable never blocks or denies an enforce. `vinctor operator audit verify
--against-anchor <head-log>` checks the live chain against the recorded heads.
This is tamper-**evident**, not tamper-**proof**; for a compliance system of
record, forward audit to durable WORM/SIEM storage.

`VINCTOR_AUDIT_SINK_REQUIRED` governs the *anchor/export* sinks above. It has no
bearing on the **durable** audit write, which is not configurable at all — see
the next section.

### No audit row, no decision

**An enforce whose durable audit write fails returns `503` and no decision.**
This is a property of the enforce path, not a setting: there is no environment
variable, no flag, and no deployment profile that turns it off or weakens it.

```text
503  {"error":"service_unavailable","reason":"audit write failed; no decision was recorded"}
```

What that buys you, and why the exact shape matters:

- **There is no `decision` field at all** — not `"deny"`, not `null`. A PEP
  parsing the body cannot read a failed audit write as a permit, and one that
  keys off `decision == "permit"` fails closed by construction.
- It holds identically for calls that would have permitted, denied, or been
  denied for a destructive action. The would-be verdict never leaks.
- **Nothing is partially written.** The audit row and the decision commit
  together, so a failed write leaves no orphan row and no forked hash chain.

The practical consequence: audit storage is on the critical path. If the audit
store is unavailable, Vinctor stops answering rather than authorizing actions it
cannot record. Size and monitor it as a dependency of enforcement, not as
telemetry.

### OTLP audit forwarding

Set `VINCTOR_AUDIT_EXPORT` to an OTLP/HTTP logs endpoint to forward a
best-effort copy of each durable audit event:

```bash
VINCTOR_AUDIT_EXPORT=otlp-http:http://otel-collector:4318/v1/logs \
  vinctor service serve
```

The exporter sends OTLP JSON (`ExportLogsServiceRequest`) on a bounded
background queue. It batches up to 32 records, retries transient network,
`408`, `429`, and `5xx` failures up to three times with exponential backoff,
and performs a bounded flush when the service closes. Audit persistence
completes first; a slow, unavailable, or full collector never changes an
enforcement decision. Invalid OTLP endpoints or delivery settings refuse
startup rather than silently disabling export.

Tune delivery without moving it onto the enforcement path:

```bash
export VINCTOR_AUDIT_EXPORT_BATCH_SIZE=64
export VINCTOR_AUDIT_EXPORT_MAX_ATTEMPTS=5
export VINCTOR_AUDIT_EXPORT_RETRY_BACKOFF_SECONDS=0.25
```

The in-memory outbound queue is not durable, so delivery remains best effort.
Use the workspace-key-gated `operator audit export` command to replay or
reconcile the authoritative durable record.

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

Python 3.11 or newer is required. This section assumes a
[source checkout](https://github.com/vinctor-ai/vinctor-core) — `tests/` and
`demo/` are not part of the published wheel.

```bash
python3.11 -m venv .venv
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

Paths in this section are in the
[source repository](https://github.com/vinctor-ai/vinctor-core). The published
wheel contains only `vinctor_core/`, `vinctor_service/`, and
`vinctor_mcp_server/`.

- `README.md` - public overview of this core package
- `AGENTS.md` - instructions for AI coding agents
- `.github/workflows/ci.yml` - public CI for tests, demo, lint, and whitespace
- [docs/next-actions.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/next-actions.md) - current work state and next tasks
- [docs/cli-design.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/cli-design.md) - local prototype CLI design and migration plan
- [docs/cli-reference.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/cli-reference.md) - per-value CLI command reference, organized by config value (--help-derived)
- [docs/local-hook-runbook.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/local-hook-runbook.md) - local service to runtime hook walkthrough
- [docs/git-boundary-demo-scenario.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/git-boundary-demo-scenario.md) - repo-scope boundary demo scenario
- [docs/threat-model.md](https://github.com/vinctor-ai/vinctor-core/blob/main/docs/threat-model.md) - per-phase threat model: what each phase does and does not defend
- [docs/decisions/](https://github.com/vinctor-ai/vinctor-core/tree/main/docs/decisions) - durable design decisions when needed
- [docs/operator-policy-authoring/](https://github.com/vinctor-ai/vinctor-core/tree/main/docs/operator-policy-authoring) - operator mapping and approval mode examples
- `src/vinctor_core/` - core authorization logic
- `src/vinctor_service/` - service-layer application helpers
- `tests/` - behavior-defining tests

## Status

Early prototype. Use for review and experimentation, not production-ready
authorization infrastructure.

The package boundaries, naming, and API surface may change.
