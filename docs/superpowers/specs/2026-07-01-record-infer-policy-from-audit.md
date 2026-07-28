# Record → Infer: bootstrapping grants from observed audit traces

Date: 2026-07-01
Status: **Proposed** — design rationale for founder review; no code yet. Cut an ADR
(next free number) if approved, then writing-plans → TDD.

Design proposal for a deterministic "infer a least-privilege policy from what the
agent actually did" capability, and — more importantly — a written record of **why
it is worth building**.

## Why build this (motivation)

1. **The blank-page problem is the adoption killer for a least-privilege tool.**
   Today an operator must hand-author scopes / issuable-bounds / grants *before* an
   agent can do useful work (see the grant/scope grammar in
   [`scope.py`](../../../src/vinctor_core/scope.py) and the policy schema in
   [`operator-policy-authoring/policy-file.md`](../../operator-policy-authoring/policy-file.md)).
   Writing correct least-privilege scopes from scratch is exactly the friction that
   makes teams either (a) not adopt, or (b) grant something broad "just to get it
   working" — which defeats the product. A security tool that is too tedious to
   configure delivers no security.

2. **Competitive parity + our natural advantage.** A widely-shared community tool,
   AgentPerms ([dev.to write-up](https://dev.to/hasanmehmood/your-ai-agent-has-sudo-i-built-a-tool-to-take-it-away-46mk)),
   ships a `record → infer` flow: run the agent in a record mode, then auto-generate
   a YAML policy from the observed `tools/call` traffic. It is a strong developer
   experience and lowers time-to-first-policy dramatically. **We can match it and go
   one better:** AgentPerms needs a dedicated *record* phase (a proxy capturing
   calls). Vinctor already persists a richer, *post-enforcement* trace of every
   decision — the `audit_events` table
   ([`sqlite.py`](../../../src/vinctor_service/sqlite.py), schema ~L76) records
   `agent_id, action, resource, scope_attempted, scope_matched, event_type
   (permitted|denied), boundary_id, runtime, created_at`, already workspace-scoped
   and indexed. **Our "record" is the audit trail we produce anyway** — no separate
   recorder, and the data is already classified into `(action, resource)` pairs,
   which is exactly the shape a grant needs.

3. **It turns the audit trail into a policy-authoring flywheel.** Observe →
   propose the minimal grant that would have permitted the legitimate actions →
   operator reviews and tightens → apply. This reinforces the "least privilege by
   default" pillar and makes the audit log (a first-class, monetizable asset) do
   double duty.

## Goal / Non-goals

**Goal:** Given observed audit events for an agent over a window, deterministically
propose the *narrowest* set of scopes (and, optionally, an issuable-bound or
auto-approval rule) that would have permitted the observed **permitted** actions —
emitted as a **reviewable artifact the operator edits before applying**, in the
existing policy-file YAML shape.

**Non-goals (each a deliberate boundary, not an oversight):**
- **No auto-apply.** Inference proposes; a human applies. Deriving standing
  authority from past behavior is inherently risk-bearing (see Risks) and must not
  be a closed loop.
- **No ML / statistical / anomaly inference.** Deterministic aggregation only —
  determinism and reviewability are core pillars; a proposed scope must be
  explainable ("you did X, so this covers X").
- **No new recorder / proxy.** Consume the audit trail we already write.
- **No blind promotion of denials into allows.** Denied events may be surfaced as
  *candidate additions*, clearly separated, never merged into the proposal silently.
- **Not real-time / adaptive.** A one-shot, operator-invoked analysis.

## Approach (deterministic)

Source: `audit_events` via the existing operator read paths
(`vinctor operator audit list` / `export --format jsonl`, and the read-only MCP
`vinctor_list_audit_events`). No new persistence, no core change — this is operator
tooling in `vinctor_service`, layered above the deterministic core.

Algorithm:
1. Select events for the target agent(s) within `--since/--until`, default to
   `event_type = action_permitted` (denied events only surface under
   `--include-denied`, tagged as candidates).
2. Collect the distinct `(action, resource)` pairs actually exercised.
3. **Default: emit exact scopes** (`action:resource`) — the narrowest possible,
   one per observed pair, each annotated with `count` and `last_seen` so the
   operator can prune rare / stale entries.
4. **Opt-in `--generalize`:** collapse sibling resources under a single terminal
   wildcard *only where the existing grammar allows it* — one terminal `/*`, no
   `.`/`..` traversal segments (reuse `scope_subsumes` / the wildcard rules in
   [`scope.py`](../../../src/vinctor_core/scope.py)). Every proposed wildcard is
   shown with "this would additionally permit: …" so widening is a conscious choice.
5. Emit YAML in the existing schema — issuable-bounds and/or an auto-approval rule
   and/or a candidate grant scope set (see
   [`policy-file.md`](../../operator-policy-authoring/policy-file.md)) — which the
   operator reviews and applies via the existing `vinctor operator policy apply
   --file`.

Proposed CLI surface (subject to cli-design review):
```
vinctor operator policy infer --agent <id> --since <ts> [--until <ts>]
    [--generalize] [--include-denied] [-o yaml|json]
```
There is intentionally **no `record` subcommand** — enforcement already records.

## Alternatives considered

- **A dedicated record-mode proxy (the AgentPerms model).** Rejected: we already
  persist a post-enforcement, pre-classified trace; a second capture path is
  redundant and would drift from the enforced reality.
- **Auto-apply the inferred policy.** Rejected: over-permissioning and
  poisoned-baseline risk (below); a security control must not grant itself.
- **ML/frequency-based generalization.** Rejected: violates the determinism /
  reviewability pillar; the operator must be able to trace every proposed scope to
  concrete observed actions.

## Risks & mitigations

- **Over-permissioning by construction.** Behavior-derived scopes can bake in more
  than intended (a one-off legitimate action becomes standing authority).
  *Mitigate:* mandatory human review; conservative default (exact scopes, no
  generalization); `count`/`last_seen` annotations so rare actions are easy to drop.
- **Poisoned baseline.** If the window includes a compromised or prompt-injected
  session, inference could legitimize malicious scopes. *Mitigate:* never
  auto-apply; infer only from windows the operator trusts; denied→allow candidates
  are separated and opt-in; surface counts so anomalies stand out.
- **Wildcard over-generalization.** *Mitigate:* `--generalize` is opt-in, bounded
  by the existing one-terminal-wildcard + no-traversal grammar, and every wildcard
  prints what it would additionally permit.

## Fit with the architecture

Builds only on data and grammar that already exist: the `audit_events` store, the
scope grammar/`scope_subsumes` helper, and the policy-file schema. `vinctor_core`
stays untouched and deterministic; the feature lives in `vinctor_service` operator
tooling. No new tables, no hosted behavior.

## Open questions (for review)

- Default window if `--since` omitted (last 7 days? require explicit?).
- First-class output target: issuable-bounds vs candidate grant vs auto-approval
  rule — recommend **issuable-bounds + a candidate grant** as the primary output.
- Generalization heuristic: purely "collapse siblings seen ≥ N times", or always
  manual? Recommend manual/opt-in only for v1.

## Decision record

If approved, cut an ADR (Status → Accepted) capturing the decision and the
"propose-only, never auto-apply" invariant, then a writing-plans plan under
`docs/superpowers/plans/` and TDD per `AGENTS.md`.
