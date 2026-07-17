# 0008 Auditing Pre-Grant-Evaluation Rejections

Date: 2026-06-21

## Status

**Accepted** (founder sign-off 2026-06-21). Direction **B** — audit the
security-relevant pre-grant rejections (see Decision) — is adopted. The
implementing slice (exact event schema, the `reason_code` enum, and the
auth-failure rate-limit/aggregation policy) is deferred to that slice; until it
lands, Vinctor's behavior is unchanged and no rejection-observability claim is
made. Surfaced by the 2026-06-21 authorization-boundary dogfood; builds on the
audit stance in [0007](0007-delegated-enforce-and-pep-identity.md).

**Implementation status (2026-06-21): Direction B is fully implemented.** Every
rejection event now carries a proper coarse `reason_code` enum (mirrored into
the legacy `reason` field so reason-keyed audit columns/queries keep working).
All three security-relevant rejection classes write operator-only events with
empty `grant_id`/`grant_ref` (no grant disclosure) and leave caller-facing
responses byte-for-byte unchanged. `action`/`resource` are retained on these
events as operator-only audit signal (read only with the workspace key) — they
are not part of the caller-facing response, so they are not a caller leak:

1. **agent↔grant mismatch** → `access_rejected` /
   `reason_code=agent_grant_mismatch`, at every grant-ownership / cross-workspace
   mismatch point of both `/v1/enforce` and `/v1/enforce/delegated` (delegated
   records the enforcing PEP separately from the subject).
2. **authentication failure** → `auth_failed` /
   `reason_code=auth_failed`, **aggregated** by an in-memory
   `AuthFailureAuditThrottle` per `(surface, source)` window. The first failure
   of a window emits a timely event immediately (`occurrence_count=1`,
   `first_seen_at == last_seen_at == now`); in-window repeats are counted in
   memory and do not emit; when the window rolls, a summary event for the
   just-closed window is emitted if it saw more than one failure
   (`occurrence_count`/`first_seen_at`/`last_seen_at` spanning the window). This
   bounds audit-store writes so a bad-credential probe cannot flood the store,
   while still giving the operator a prompt signal and an accurate count.
   Attributed to the surface/boundary only (no resolvable principal). The
   throttle is in-memory/per-process — it resets on restart (at worst a dropped
   pending summary and a small post-restart burst); a durable variant can follow
   if needed.
3. **out-of-bounds grant issuance** → `grant_issue_rejected`, for the
   scope-outside-bounds (`reason_code=scope_outside_issuable_bounds`),
   bounds-not-found (`reason_code=issuable_bounds_not_found`), and TTL-over-max
   (`reason_code=ttl_exceeds_issuable_max`) ceilings. The status code is **403**
   on **both** issuance paths: the direct `POST /v1/grants`
   (`grant_http.py`) and the approval path that issues on approve
   (`grant_request_http._decision_failure_status`, which maps these three reasons
   via `_ISSUABLE_BOUNDS_REASONS` to 403 to match the direct path). The approval
   path returned 409 before the 2026-06-24 cold-e2e fix.
4. **Malformed input** (e.g. `scope_invalid`) remains deliberately un-audited.

## Context

`/v1/enforce` evaluates a request in stages: authenticate the caller's
`X-Agent-Key`, resolve the named `grant_ref`, check the grant belongs to the
caller (`grant.agent_id == request.agent_id AND grant.workspace_id ==
request.workspace_id`), then run the identity-agnostic PDP core
(`evaluate_enforce`) to permit or deny on scope. Grant issuance and bounds are a
separate operator path.

Today the audit trail records **only decisions reached against a valid
(agent, grant) pair, plus grant lifecycle**: `action_permitted`,
`action_denied`, `grant_issued`, `grant_revoked`. A hands-on dogfood
(2026-06-21) confirmed that everything rejected **before** grant-scope
evaluation produces **no audit event at all**. The full audit for the run held
14 events (3 `grant_issued`, 5 `action_permitted`, 5 `action_denied`,
1 `grant_revoked`) and **zero** events for any of:

- **Agent↔grant mismatch** — a caller with a valid `aak_` key naming another
  agent's `grant_ref` ("grant_ref … does not belong to the requesting agent").
  This is the tenant/agent-isolation invariant doing its job — but it is also the
  single clearest *misuse / lateral-movement* signal Vinctor can observe: a
  holder of agent A's key attempted to spend agent B's authority.
- **Authentication failure** — an invalid/unknown `X-Agent-Key` (`401`). A
  defender wants to see credential probing.
- **Out-of-bounds grant issuance** — an operator request to issue a grant
  outside an agent's issuable bounds (`403 scope_outside_issuable_bounds`). An
  attributable operator action (mis-provisioning or over-reach).
- **Malformed request** — e.g. a wildcard/invalid resource (`400 scope_invalid`).
  Low security signal.

This silence is, at least in part, **deliberate**. ADR 0007 states that
cross-workspace and bad-subject delegated requests "fail closed with a generic
`forbidden`/`grant_not_found` and write no audit event, exactly like the
existing path." That posture conflates two separable properties:

1. **Caller-facing non-disclosure** — the *response* to the caller must not
   confirm or deny the existence of a grant/agent, must not leak `grant_ref` or
   ids, and must fail closed. This is correct and must not change.
2. **Operator-facing observability** — the *internal* audit trail, which is
   read only with the workspace key by the operator/SOC, never returned to the
   caller.

Auditing a rejection internally does **not** weaken (1): the attacker still gets
a generic, leak-free, fail-closed response; only the operator gains a record.
Vinctor currently forgoes (2) for rejections as a side effect of (1). For a
runtime-authorization security product, the absence of an audit record for
"someone tried to use a grant that isn't theirs" is a real observability gap.

## Decision (proposed)

Add **operator-only** audit events for security-relevant pre-grant-evaluation
rejections, while leaving every **caller-facing response unchanged** (still
generic, fail-closed, non-disclosing). Concretely:

1. **Agent↔grant mismatch → audit (high priority).** Emit a first-class audit
   event (e.g. `access_rejected`, `reason_code = agent_grant_mismatch`). The
   caller is a valid, authenticated agent, so the event is **attributable** to
   the resolving `agent_id` and `boundary_id`. This is the highest-value addition.
2. **Authentication failure → audit, aggregated.** The key is invalid, so no
   `agent_id` is resolvable; attribute to source/`boundary_id` only. Emit
   **rate-limited or aggregated** events (count + first/last seen per
   source/window), not one row per attempt, so a probing attacker cannot flood
   the audit store (log-amplification DoS).
3. **Out-of-bounds grant issuance → audit.** An operator action authenticated by
   the workspace key; attributable and low-volume. Emit
   `reason_code = scope_outside_issuable_bounds`.
4. **Malformed request (`scope_invalid`, etc.) → do not audit** (or debug-level
   only). Low signal, high noise, no security value.

**Redaction invariants (carried from 0007 and the F5 deny-reason discipline):**
every new event records event type, a coarse `reason_code` enum, `agent_id`
(when resolvable), `boundary_id`, and timestamp — and **never** the raw key, the
offending `grant_ref`, internal grant ids, or tool input. The caller-facing
response is byte-for-byte unchanged.

## Alternatives considered

- **A. Status quo (audit nothing pre-grant).** Simplest; preserves a single
  rule ("only valid decisions are audited"). Rejected: leaves grant-misuse and
  credential probing invisible to the operator.
- **B. Audit security-relevant rejections only (recommended).** Items 1–3
  above. Captures the misuse/probe/over-issuance signals; excludes noisy
  malformed-input. Balances observability against volume.
- **C. Audit every rejection including malformed input.** Maximal visibility but
  invites log flooding from trivially-malformed traffic and adds little security
  signal over B.

## Consequences

- Operators/SOC can detect cross-agent grant misuse, credential probing, and
  operator over-issuance — the events most indicative of compromise or
  mis-provisioning — instead of seeing only successful-path decisions.
- Caller-facing non-disclosure and fail-closed behavior are preserved exactly;
  this ADR revises only the *internal* audit silence, not any response. It
  therefore amends 0007's "write no audit event" stance **for the operator audit
  trail only**, not for what the caller observes.
- Tenant isolation and the identity-agnostic PDP core are unchanged; this is
  purely additive observability on the reject paths.
- Cost: an audit write on reject paths. The authentication-failure path must be
  rate-limited/aggregated to avoid an attacker turning audit logging into a DoS
  amplifier.
- **Open for sign-off:** the exact event schema, the `reason_code` enum, and the
  rate-limit/aggregation policy for auth failures are deferred to the
  implementing slice after this decision is accepted. Until then Vinctor's
  behavior is unchanged and no claim of rejection observability is made.
