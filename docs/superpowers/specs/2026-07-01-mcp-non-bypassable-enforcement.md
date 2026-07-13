# Non-bypassable enforcement for MCP tool calls (MCP as the first resource-side PEP)

Date: 2026-07-01
Status: **Proposed** — awaiting founder sign-off. Extends the Phase 1.8 mechanism
([ADR 0007](../../decisions/0007-delegated-enforce-and-pep-identity.md)) to the MCP
surface. Cut an ADR (next free number) if approved. Note: the *code* lives in an
adapter outside `vinctor_core` (see "Fit"); this spec lives here because it extends
the enforcement model and the threat model.

Design proposal for making enforcement **non-bypassable for MCP tool calls**, and a
written record of **why it is worth building now**.

## Why build this (motivation)

1. **Our shipping enforcement is cooperative, and we say so.** Phase 1 (the
   agent-side `PreToolUse` hook) is honest but bypassable: per the
   [threat model](../../threat-model.md) (L75), *"it is bypassable by an agent that
   controls its own runtime."* That candor is right, but it is also the single
   biggest thing a security buyer discounts. The path from "deterrent/detective
   control" to "control" runs through non-bypassable enforcement.

2. **The mechanism already exists — it just has no instrumented resource.** Phase
   1.8 (ADR 0007) shipped everything needed for *resource-side*, non-bypassable
   enforcement: delegated enforce (`/v1/enforce/delegated` in
   [`v1_enforce.py`](../../../src/vinctor_service/v1_enforce.py) ~L107), workspace-
   scoped `pep_` PEP keys, grant-bound `vat_` subject tokens (ADR 0007 Model 2), and
   audit that records the enforcing PEP principal separately from the subject. What
   is missing is a *first real PEP*. Today MCP in this repo is **control-plane only**
   (`vinctor_mcp_server/` — inspection + opt-in approval; it never calls
   `/v1/enforce`). So the enforcement path is built but unused on any concrete
   surface.

3. **MCP is the ideal first resource to make non-bypassable — because complete
   mediation is actually achievable there.** Phase 1.8's non-bypassability is
   *conditional on complete mediation* (threat model L151–206). For arbitrary native
   shell/file calls that condition is hard to meet. MCP is different: it has a single,
   well-defined transport (stdio today; HTTP/SSE later) between client and server, so
   **every `tools/call` can be interposed**. MCP is where "mediate every path" is
   realistic, and it is a high-value surface (databases, GitHub, Slack, filesystem
   servers).

4. **Competitive: this is exactly where AgentPerms is stronger than our hook — for
   the MCP subset.** AgentPerms
   ([dev.to write-up](https://dev.to/hasanmehmood/your-ai-agent-has-sudo-i-built-a-tool-to-take-it-away-46mk))
   rewrites the MCP client config so **every server launches through a transparent
   stdio proxy** (`Agent → proxy → MCP server`); denied calls *"return a synthetic
   JSON-RPC error to the client without forwarding."* The agent cannot reach the
   server except through the proxy — genuinely harder to bypass than our cooperative
   hook, for that surface. Instrumenting MCP as a Vinctor PEP closes this specific
   gap while keeping our differentiator (the *deterministic grant + identity + audit*
   model, not just a filter) and reusing the delegated-enforce path we already ship.

## Goal / Non-goals

**Goal:** A Vinctor **MCP enforcement proxy (PEP)** on the MCP transport between
client and server that, for each `tools/call`: maps `(server, tool, args) →
(action, resource)`, calls `/v1/enforce/delegated` (PEP key + optional subject
token), forwards on **permit**, and on **deny / unreachable / malformed** returns a
synthetic JSON-RPC error **without forwarding** (fail-closed). Non-bypassable *for
the MCP path* because the client reaches the server only through the proxy.

**Non-goals (deliberate boundaries):**
- **Native (non-MCP) tool calls** — still Phase 1 hook territory; out of scope here.
- **Credential brokering / ambient-credential stripping** — Phase 2, not built.
- **MCP tool-poisoning / schema-pinning** — a distinct, *composable* concern (cf.
  `mcp-scan`, AgentPerms' tool pinning). Note as a follow-up, not a claim here.
- **Proving completeness of mediation for the underlying resource.** We mediate the
  MCP path; side doors and ambient credentials to the same resource are out of scope
  and must be stated honestly (same posture as threat-model Phase 1.8).

## Approach

Architecture (mirrors the proven interposition pattern):
```
MCP client (Claude Desktop / Cursor / …)
    │   (client config rewritten to launch the proxy)
    ▼
Vinctor MCP PEP  ──map(server,tool,args)→(action,resource)──▶ POST /v1/enforce/delegated
    │                                                          (X-PEP-Key: pep_… , X-Subject-Token: vat_…)
    │  permit → forward tools/call            deny/unreachable/malformed → synthetic JSON-RPC error, do NOT forward
    ▼
real MCP server
```

- **Interposition:** stdio first (the common local case; matches the surface
  AgentPerms covers today), HTTP/SSE next. The proxy must be *transparent* — pass
  through `initialize`, `tools/list`, capabilities, and errors faithfully; only
  `tools/call` is gated.
- **Mapping `(server, tool, args) → (action, resource)`:** reuse/extend the MCP
  classifiers that already exist on the hook side
  (`mcp__server__tool` → `action:resource`, with filesystem/github/slack examples in
  `vinctor-claude-code-hook`). Unmapped tools take a configured default verdict
  (see Open questions).
- **Identity & audit (reused, unchanged):** the PEP authenticates with a
  workspace-scoped `pep_` key; the subject agent is *proven* when a `vat_` subject
  token is presented (ADR 0007 Model 2). Audit records `enforcing_principal = the
  MCP PEP`, separate from the subject `agent_id` — already supported.
- **Fail-closed:** any non-permit outcome (deny, Vinctor unreachable, malformed
  response, missing boundary when required per ADR 0009-B) blocks the call before it
  reaches the server.

## Why this is non-bypassable — and the honest limits

Non-bypassable for the MCP path **iff**: (a) the client can reach the server *only*
through the proxy (config points at the proxy and the server is not independently
reachable), (b) the proxy fails closed, and (c) every MCP path is proxied.

Residual bypasses — to be documented, not glossed (mirroring threat-model Phase
1.8):
- **Config-rewrite bypass.** An agent that can edit its own MCP client config could
  drop the proxy. Hardening: operator-/managed-device-controlled config (cf. the
  managed-device note in the threat model). This is the same *class* as
  hook-disable, but materially harder when the config is operator-owned.
- **Side doors / ambient credentials.** If the agent already holds a credential that
  reaches the same resource *without* going through MCP, the MCP PEP never sees it.
  Unchanged Phase 1.8 caveat.
- **Mapping fidelity.** A wrong `(action, resource)` classification is a wrong
  verdict — the same trust boundary the hook has. Mitigate with per-server
  classifiers and a conservative default for unmapped tools.

Net: **stronger than the cooperative hook for the MCP surface, still bounded.** Say
exactly that.

## Alternatives considered

- **Leave MCP in the cooperative Phase-1 hook only (status quo).** Rejected: it
  leaves the most valuable, cleanly-interposable surface bypassable when the
  delegated mechanism to fix it already ships.
- **Make the control-plane MCP server also enforce.** Rejected: it is
  inspection/approval by design (`AGENTS.md`) and is not on the tool-call data path.
- **HTTP-gateway only.** A subset; stdio is the common local case (Cursor / Claude
  Desktop) — do stdio first, HTTP/SSE next.

## Fit with the architecture / boundaries

- **Core is untouched.** This reuses `/v1/enforce/delegated` + `pep_`/`vat_` keys
  exactly as shipped. `AGENTS.md` forbids MCP hooks and raw interception *in
  `vinctor_core`*, so the **proxy code lives in an adapter** (a sibling repo, e.g.
  alongside the hook family), not in core. The spec lives in core docs because it
  extends the enforcement/threat model.
- **Threat model gains an "MCP PEP" subsection** when shipped, stating the
  non-bypassability precondition and residual bypasses above.

## Open questions (for review)

- Default verdict for **unmapped** MCP tools: fail-closed deny, or allow-with-audit?
  (Recommend policy-driven, default deny for a security posture.)
- Home repo for the adapter (new `vinctor-mcp-pep` vs the hook family).
- Fold tool-schema pinning in now, or ship enforcement first and pin later?
- Config-rewrite hardening story for managed vs BYOD devices.

## Decision record

If approved, cut an ADR (Status → Accepted) recording the decision to instrument
MCP as the first resource-side PEP and the exact non-bypassability precondition,
then a writing-plans plan and TDD per `AGENTS.md`.
