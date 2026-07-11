# 0010 — Infer scope proposals from audit traces (record → infer)

- Status: Accepted (founder, 2026-07-02)
- Date: 2026-07-02
- Spec: [`superpowers/specs/2026-07-01-record-infer-policy-from-audit.md`](../superpowers/specs/2026-07-01-record-infer-policy-from-audit.md)
- Plan: [`superpowers/plans/2026-07-02-record-infer.md`](../superpowers/plans/2026-07-02-record-infer.md)

## Context

Hand-authoring least-privilege scopes before an agent can work is the dominant
onboarding friction — teams either don't adopt or grant something broad "to get it
working," which defeats the product. We already persist a post-enforcement
`(action, resource)` trace in `audit_events`, so we can *propose* a minimal grant
from what an agent actually did — with no separate recorder (unlike a proxy-based
tool that needs a record phase). The design and motivation are in the spec above.

## Decision

Add a **deterministic** scope-inference capability with two layers:

1. **Pure core** — `vinctor_core.infer.propose_scopes(observations, *,
   generalize=False)` returns `ScopeProposal`s. It is DB/HTTP-agnostic (takes
   already-collected `Observation(action, resource, count, last_seen)` values),
   reuses the existing scope grammar (`vinctor_core.scope`), and is the home for
   the algorithm and its tests.
   - **Default (exact):** one proposal per distinct valid `(action, resource)` —
     the narrowest possible. Invalid actions/resources are dropped (they cannot
     become grant scopes). Duplicates aggregate (count summed, latest `last_seen`).
   - **Opt-in `generalize`:** collapse a group of siblings under a single terminal
     wildcard `action:parent/*` **only when the parent has ≥ 2 path segments** and
     ≥ 2 distinct child resources were observed. This deliberately refuses to
     create top-level `category/*` wildcards (e.g. it will *not* widen
     `send:net/internal` + `send:net/external` into `send:net/*` — the exfil
     footgun); it only deepens existing structure (`read:repo/feature/a` +
     `read:repo/feature/b` → `read:repo/feature/*`). Every wildcard proposal
     carries `covers` (the concrete scopes it subsumes) so the widening is
     auditable.
   - Deterministic ordering (sorted by scope); no wall-clock/random input.

2. **Service surface** — a `vinctor operator policy infer` CLI (in
   `vinctor_service`) reads `audit_events` for the target agent/window, aggregates
   `(action, resource)` + count + latest timestamp, calls `propose_scopes`, and
   emits a **reviewable YAML/JSON proposal** in the existing policy-document shape.
   It is **propose-only**: it never applies policy. The operator reviews, tightens,
   and applies via the existing `vinctor operator policy apply`.

**Invariant of record:** inference *proposes*; a human *applies*. There is no closed
loop from observed behavior to standing authority.

## Consequences

- New `vinctor_core.infer` module (pure, tested) + a `policy infer` operator
  command. No new persistence; consumes the existing audit store and scope grammar.
- `vinctor_core` stays deterministic and agnostic; audit-reading and YAML live in
  `vinctor_service`, per the layering in `AGENTS.md`.
- Over-permissioning / poisoned-baseline risk is mitigated structurally: exact by
  default, `generalize` refuses top-level wildcards, `covers`/`count`/`last_seen`
  annotations let the operator prune, and nothing is auto-applied. These risks and
  mitigations are documented in the spec.
- The generalization rule (parent depth ≥ 2) is a deliberate safety default; if a
  future need arises to collapse shallow siblings it must be a separate, explicitly
  reviewed decision (superseding note here).
