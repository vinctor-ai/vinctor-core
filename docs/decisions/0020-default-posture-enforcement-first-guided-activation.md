# ADR 0020: Default posture — enforcement-first, activated by guidance not by defaults

## Status

Accepted. 2026-07-18.

## Context

Vinctor ships mandating none of its own primitives, and nobody chose that.

All three enforcement mandates default off, per-agent, with an absent setting
meaning off:

- `agent_enforcement_settings` declares `require_boundary`,
  `require_subject_token`, and `require_pop` with `DEFAULT 0` (SQLite) /
  `DEFAULT FALSE` (Postgres). A freshly-added agent is required to present no
  boundary, no subject token, and no proof-of-possession.

Each off was a defensible *local* decision — safe rollout, backwards
compatibility (the per-flag `require_*_set` presence bits show how carefully
each was handled in isolation). But the *composite* posture — "the product
enforces nothing until someone turns it on" — was never a decision anyone made.
It is the sum of three independent "make this opt-in" calls.

Silent-by-default has two failure modes, and the second is the one that governs:

1. **False security.** A user points agents at Vinctor, sees it running, and
   believes they are protected. They are not: every presence check passes.
2. **Never activated.** An enforcement product that starts in observe and stays
   there never proves its value, so the user drifts away without ever turning it
   on. A tool nobody activates is a tool nobody keeps. For adoption this is the
   larger risk: observe-first quietly optimizes for abandonment.

## Decision

**1. Vinctor's identity is enforcement-first.** It is a runtime authority (a
PDP) for agent actions, not an observability tool you may later escalate.
Observe is a starting state on the way to enforcement, not the product.

**2. Enforcement-first does NOT mean defaults-on.** Shipping a mandate enabled
would hard-deny, on day one, every existing agent that presents no boundary /
token / PoP — breaking each new adopter the moment they connect. That is a
*faster* churn than silence, not a cure for it. The schema defaults stay off;
activation is driven by guidance, not by flipping defaults.

**3. The documented front door is a staged ramp: observe → simulate → enforce.**
`simulate` is the bridge, and it already exists. `simulate_v1_contract`
"calculate[s] and audit[s] an enforce result without turning it into a gate": it
runs the same `evaluate_enforce` core, returns a `would_decision`
(permit/deny), and records `action_would_permit` / `action_would_deny` audit
events. It evaluates against the *currently-active* mandate settings — with
`require_boundary` off, `simulate` also runs with it off, so it previews what
enforce would do right now, not what enabling a mandate would do. It proves
value ("Vinctor would have denied these three actions" under today's posture)
without breaking anything, which creates the pull to enforce that
observe-alone lacks. Previewing the effect of *enabling* a currently-off
mandate is a different capability — it needs a hypothetical-policy input to
`simulate` (passing candidate settings instead of reading the stored ones),
which does not exist today and is a possible future extension, not something
the current ramp provides.

**4. Install actively pushes toward setup.** A first-run / `init` step surfaces
"0 mandates active — enable enforcement for your first agent: `<command>`", and
a posture readout (a `doctor`/status surface, or an extended readiness output)
never hides `ENFORCEMENT: OFF`. Neither exists today — the CLI has only
`local start` — so both are net-new.

## Consequences

- **Positioning shifts.** Docs and messaging commit to "runtime authority for
  agents," not "observability you can escalate." "Installed and running" must
  never be allowed to read as "protected" — the loud posture signal exists to
  break that inference.
- **New surfaces, all greenfield**: first-run / `init` guidance; a posture/status
  readout; and the observe → simulate → enforce journey as documented product
  flow rather than three unrelated features.
- **`simulate` becomes load-bearing for onboarding**, not just a debugging aid.
  Its `action_would_*` audit events are the value-demonstration data the ramp
  depends on — worth keeping that in mind for any change to simulate or to audit
  retention.
- **A posture-profile concept** (`observe` / `standard` / `strict`, so activation
  is one decision rather than N per-agent flags) is a natural extension. Deferred
  until the journey shows it is needed — not built speculatively.
- **No schema-default change, no behavior flip.** This is guidance, UX, and docs
  over the existing permissive default, so it does not break current adopters —
  it keeps the safe-rollout property while removing the adoption dead-end.

## Notes

Item 2 of the verdict session on "decisions nobody chose." The founder's
decisive reason was adoption, not only security: observe-first means most users
never advance, never see value, and abandon Vinctor. Enforcement-first with
guided activation answers that while preserving the one real virtue of the old
default — no day-one breakage — by moving the ramp into `simulate` and into
first-run guidance instead of into the schema.
