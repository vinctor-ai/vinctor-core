# 0011 — Instrument MCP as the first resource-side PEP (non-bypassable MCP enforcement)

- Status: Accepted (founder, 2026-07-02) — decision to pursue; **implementation
  lives in an adapter, not this repo** (see Consequences).
- Date: 2026-07-02
- Spec: [`superpowers/specs/2026-07-01-mcp-non-bypassable-enforcement.md`](../superpowers/specs/2026-07-01-mcp-non-bypassable-enforcement.md)
- Plan: [`superpowers/plans/2026-07-02-mcp-non-bypassable-pep.md`](../superpowers/plans/2026-07-02-mcp-non-bypassable-pep.md)
- Builds on: [ADR 0007](0007-delegated-enforce-and-pep-identity.md) (delegated enforce
  + PEP identity), [ADR 0009](0009-mandatory-boundary-enforcement.md) (require-boundary).

## Context

Phase 1 (the agent-side hook) is cooperative and **bypassable by an agent that
controls its runtime** (threat model). Phase 1.8 (ADR 0007) already shipped the
mechanism for *non-bypassable* resource-side enforcement — delegated enforce
(`/v1/enforce/delegated`), workspace-scoped `pep_` keys, grant-bound `vat_` subject
tokens, and audit that records the enforcing principal separately — but no resource
is instrumented as a PEP yet, and MCP here is control-plane-only (it never calls
enforce). MCP is the ideal first PEP: its transport (stdio; HTTP/SSE later) allows
**complete mediation** of every `tools/call`, the precondition Phase 1.8 needs.
A community proxy (AgentPerms) already demonstrates the value on the MCP surface —
it is stronger than our cooperative hook there. Full motivation is in the spec.

## Decision

Instrument MCP as the first **resource-side PEP** via a Vinctor **MCP enforcement
proxy** that sits on the MCP transport between client and server: for each
`tools/call`, map `(server, tool, args) → (action, resource)`, call
`/v1/enforce/delegated` (with a `pep_` key and optional `vat_` subject token),
forward on **permit**, and on **deny / unreachable / malformed / missing required
boundary** return a synthetic JSON-RPC error **without forwarding** (fail-closed).
It is non-bypassable *for the MCP path* because the client reaches the server only
through the proxy.

Honest scope, to be stated wherever this is described: non-bypassable **iff** the
client reaches the server only via the proxy, the proxy fails closed, and every MCP
path is proxied. Residual bypasses — config-rewrite (agent edits its own MCP
config), side doors / ambient credentials to the same resource, and mapping
misclassification — remain and must be documented, not glossed. "Stronger than the
hook for MCP, still bounded."

## Consequences

- **No `vinctor_core` change and no code in this repo.** `AGENTS.md` forbids MCP
  hooks / raw interception in core; the proxy is an **adapter** (a new repo, e.g.
  `vinctor-mcp-pep`, in the hook family) that consumes the already-shipped
  `/v1/enforce/delegated` contract + `pep_`/`vat_` keys unchanged. This ADR and its
  spec live in core docs only because they extend the enforcement/threat model.
- When the adapter ships, the **threat model gains an "MCP PEP" subsection** stating
  the non-bypassability precondition and the residual bypasses above.
- Open items reserved for the plan/implementation: default verdict for *unmapped*
  MCP tools (recommend fail-closed deny), the adapter's home repo, whether to fold
  tool-schema pinning in now, and config-rewrite hardening for managed vs BYOD.
- Sequencing: this decision is recorded now; the adapter implementation is a
  separate effort (see the plan) and is **not** part of the record→infer slice.
