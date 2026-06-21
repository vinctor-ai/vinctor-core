# 0009 Mandatory Boundary Enforcement (Opt-In)

Date: 2026-06-21

## Status

**Accepted** (founder sign-off 2026-06-21). Direction **B** — an opt-in,
operator-controlled `require_boundary` setting (per workspace/agent, default
**off**); when set, an `/v1/enforce` request for that scope with an absent or
unusable boundary **fails closed** (`boundary_required`) — is adopted.

The implementing slice (exact storage shape — whether the flag is
workspace-level, agent-level, or both — the `boundary_required` deny reason, and
the operator surface to set the flag) is deferred to that slice. Until it lands,
Vinctor's behavior is unchanged and no mandatory-boundary claim is made.
Surfaced by the 2026-06-21 boundary fail-closed dogfood.

## Context

`/v1/enforce` accepts an optional `X-Vinctor-Boundary-Id` header. The PDP core
(`vinctor_core/enforce.py:_resolve_boundary`) treats it as follows:

- **Header present, boundary usable** (exists, active, same workspace): the
  decision proceeds and the boundary is recorded in audit.
- **Header present, boundary unusable** (unknown / disabled / wrong workspace):
  **fail-closed deny** (`boundary_not_found` / `boundary_inactive` /
  `boundary_wrong_workspace`).
- **Header absent**: `_resolve_boundary` returns `None` and the request is
  evaluated **with no boundary check** — it permits on grant scope alone, and the
  audit event records `boundary_id = null`.

The dogfood verified all three paths. The consequence is that **"fail-closed"
applies only to a *supplied-but-unusable* boundary, not to the *absence* of a
boundary.** A caller that simply omits the header bypasses the boundary layer
entirely. Two implications:

1. The `disable` kill-switch (`POST /v1/boundaries/{id}/disable`) only bites
   callers that keep sending that boundary's id. A compromised or buggy hook can
   evade a disabled boundary by dropping the header.
2. There is no server-side way to **require** that decisions for a given
   agent/workspace flow through a registered boundary. That guarantee currently
   rests entirely on the client-side hook always sending the header.

For a runtime-authorization product whose boundary is meant to be an operator
control point (attribution + a kill-switch), "the control only works if the
client cooperates" is a real gap.

## Decision (proposed)

Add an **opt-in, operator-controlled "require boundary"** setting, scoped to a
workspace (and/or a specific agent). When set, every `/v1/enforce` request for
that scope **MUST** carry a valid, active boundary; a request with an absent (or
unusable) boundary **fails closed** with a dedicated reason (e.g.
`boundary_required`). Default **off**, so existing behavior is unchanged.

This makes the boundary a real server-side control:

- `disable` becomes enforceable: for a hardened agent/workspace, a disabled **or
  absent** boundary now denies, so the kill-switch cannot be evaded by dropping
  the header.
- Operators can harden sensitive workspaces without changing the default
  posture for everyone else.
- The setting is managed with the workspace key (operator credential) and the
  `boundary_required` denial should be audited (consistent with the rejection
  auditing in ADR 0008).

## Alternatives considered

- **A. Status quo (boundary fully opt-in).** Simplest; no new state. Rejected as
  the default-forever posture: it leaves the documented bypass and a kill-switch
  that the client can evade.
- **B. Opt-in `require_boundary` per workspace/agent (recommended).** Adds one
  operator-controlled flag; default off (backward-compatible); closes the
  drop-the-header bypass for hardened scopes and makes `disable` effective.
- **C. Always-mandatory boundary.** Maximally strict but breaks every caller not
  already sending the header and removes the lightweight default. Too broad for
  the current local/preview posture.

## Consequences

- Operators gain a real, server-side way to require boundary-mediated
  enforcement for sensitive agents/workspaces; the `disable` kill-switch becomes
  effective there (absent/disabled boundary → deny).
- Default-off preserves the current opt-in behavior and all existing callers.
- This is defense-in-depth, **not** proof of origin: a compromised hook that
  knows a valid, active boundary id could still present it. Proving that an
  enforce request genuinely originated from the named adapter is a separate,
  harder question tied to the agent/boundary identity-proof OPEN DECISION in
  [0007](0007-delegated-enforce-and-pep-identity.md); this ADR only closes the
  trivial "omit the header" bypass and makes `disable` enforceable.
- New state (the per-workspace/agent flag) and a `boundary_required` deny reason
  are added; the exact storage shape and whether the scope is workspace-level,
  agent-level, or both are deferred to the implementing slice after sign-off.
