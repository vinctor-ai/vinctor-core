# MCP Non-Bypassable Enforcement (MCP as resource-side PEP) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans /
> subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.
> **Note:** the implementation lives in a NEW ADAPTER repo, not `vinctor-core`
> (`AGENTS.md` forbids MCP hooks / raw interception in core). This plan is recorded
> here because the decision extends the enforcement/threat model
> ([ADR 0011](../../decisions/0011-mcp-resource-side-pep.md)); execute it in the
> adapter repo.

**Goal:** A Vinctor MCP enforcement proxy that makes MCP `tools/call` non-bypassable
by mediating every call through `/v1/enforce/delegated`, fail-closed.

**Architecture:** `MCP client → Vinctor MCP PEP (stdio) → real MCP server`. The
client config is rewritten so the server is only reachable via the proxy. Each
`tools/call` is mapped to `(action, resource)` and authorized via delegated enforce
(`pep_` key + optional `vat_` subject token); non-permit ⇒ synthetic JSON-RPC error,
never forwarded. Reuses the already-shipped Phase-1.8 contract unchanged.

**Tech Stack:** TBD at repo bootstrap — recommend the same stack as the existing
hook family for reuse of the `(server, tool, args) → (action, resource)` classifiers
already present in `vinctor-claude-code-hook`.

---

## Prerequisites / decisions to lock before coding

- [ ] **Adapter repo home.** New `vinctor-mcp-pep` vs folding into the hook family.
      Recommend a new repo to keep the interposition surface isolated.
- [ ] **Default verdict for unmapped MCP tools.** Recommend **fail-closed deny**
      (security posture); make it policy-configurable.
- [ ] **stdio first**, HTTP/SSE next (matches the common local case and the surface
      a comparable proxy already covers).
- [ ] **Tool-schema pinning** (detect MCP tool poisoning) — in scope now or a
      follow-up? Recommend follow-up; it is a composable, separate concern.

## Task outline (execute in the adapter repo, TDD)

### Task 1 — Transparent stdio proxy skeleton
- Spawn/relay to the real MCP server; pass through `initialize`, `tools/list`,
  capabilities, and errors faithfully. Test: a mock MCP server round-trips
  unmodified for non-`tools/call` traffic.

### Task 2 — Gate `tools/call` via delegated enforce
- Intercept `tools/call`; map `(server, tool, args) → (action, resource)` (reuse the
  hook classifiers); POST `/v1/enforce/delegated` with `X-PEP-Key` (`pep_…`) and, if
  present, `X-Subject-Token` (`vat_…`). Permit → forward; deny/unreachable/malformed
  → synthetic JSON-RPC error, **do not forward**. Test: permit forwards; each
  non-permit path returns the error and never reaches the mock server (fail-closed).

### Task 3 — Config rewrite (interposition)
- Rewrite the MCP client config so every server launches through the proxy (the
  non-bypassability mechanism). Test: after rewrite, the client's server command
  points at the proxy; original command preserved for the proxy to launch.

### Task 4 — Unmapped-tool default + audit correlation
- Apply the configured default verdict for unmapped tools; confirm audit shows
  `enforcing_principal = <mcp-pep>` distinct from the subject `agent_id` (server-side
  behavior already exists — assert end-to-end).

### Task 5 — Threat-model update (back in vinctor-core docs)
- Add an "MCP PEP" subsection to `docs/threat-model.md` stating the
  non-bypassability precondition (client reaches server only via proxy; fail-closed;
  every path proxied) and the residual bypasses (config-rewrite, side doors / ambient
  credentials, mapping fidelity). This is the only change that lands in `vinctor-core`.

## Honesty gate (must hold before any "non-bypassable" claim)

Claim non-bypassability **only** as: "for the MCP path, conditional on the client
reaching the server solely through the proxy, fail-closed behavior, and complete
proxying — stronger than the cooperative hook, still bounded." Never imply it closes
side doors, ambient credentials, or a self-editing client config.
