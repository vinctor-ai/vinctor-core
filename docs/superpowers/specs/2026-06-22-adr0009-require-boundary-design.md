# ADR 0009-B — Opt-in `require_boundary` (per-agent) Design

Date: 2026-06-22
Status: Design approved (founder, 2026-06-22). Next: writing-plans → TDD.

Implements direction **B** of
[ADR 0009](../../decisions/0009-mandatory-boundary-enforcement.md) (Accepted): an
opt-in, operator-controlled `require_boundary` setting. Direction B is already
decided; this spec settles the deferred implementing-slice details. Scope decision
(founder, 2026-06-22): **per-agent**.

## Problem (recap)

`/v1/enforce` accepts an optional `X-Vinctor-Boundary-Id`. A *supplied-but-unusable*
boundary already fails closed (`boundary_not_found` / `boundary_inactive`), but an
**absent** boundary skips the check entirely and permits on grant scope alone. So
the `disable` kill-switch is evadable by simply omitting the header, and there is
no way to require that a given principal's decisions flow through a boundary.

## Goal / Non-goals

**Goal:** let an operator mark a specific agent as `require_boundary`; when set, an
`/v1/enforce` (and `/v1/enforce/delegated`) request for that agent with an
**absent** (or empty) boundary fails closed with `boundary_required`. Default off →
existing behavior is byte-for-byte unchanged.

**Non-goals (deferred follow-ups):**
- Workspace-level or workspace-default + agent-override scope (this slice is
  per-agent only).
- A policy-file (declarative) surface for the flag (CLI only this slice).
- Re-labeling the *unusable*-boundary denials as `boundary_required` — those keep
  their specific reasons (`boundary_not_found`/`boundary_inactive`) and already
  fail closed. The flag only closes the **absent** gap.
- mTLS/DPoP and any origin-proof (out of scope for ADR 0009 entirely).
- Plumbing `require_boundary` through the parallel `evaluate_policy` /
  `authorize_action` library surface (`vinctor_core/policy.py`,
  `vinctor_service/authorize.py`): it builds its own `EnforceInput`, is **not** wired
  to any HTTP route (so not a runtime bypass of `/v1/enforce`), and will simply
  default `require_boundary=False`. Parity there is a follow-up.

## Key invariant

**The flag changes exactly one thing: when set, a truly-absent boundary (the
`X-Vinctor-Boundary-Id` header not sent → `boundary_id is None`) on an enforce for
that agent denies (`boundary_required`) instead of permitting.** Everything else is
unchanged — usable boundary → proceed; unusable boundary → its existing fail-closed
deny; an empty/whitespace header already denies today (`boundary_not_found`, via a
registry miss) and continues to, with or without the flag; flag unset → current
behavior for every case.

## Design

### 1. Storage — a dedicated per-agent settings table

A new table `agent_enforcement_settings`, keyed by `(workspace_id, agent_id)`,
with a `require_boundary` boolean (stored 0/1) and `updated_at`. It is **separate**
from `agent_issuable_scope_bounds` because that row only exists for agents the
operator has issued issuable bounds to; an agent can receive/enforce grants without
such a row, and must still be hardenable.

- New `AgentEnforcementSettingsRepository` (Protocol + `InMemory…` twin in
  `repositories.py` alongside `SubjectTokenRepository`; `SQLite…` twin in
  `sqlite.py`), wired as a field on both `InMemoryV1Service` and `SQLiteV1Service`.
  Place the Protocol + InMemory twin in `repositories.py` — do **not** follow the
  outlier `InMemoryAgentIssuableScopeBoundsRepository`, which lives in `grants.py`.
- Methods: `get_require_boundary(*, workspace_id, agent_id) -> bool` (returns
  **False** when no row exists) and `set_require_boundary(*, workspace_id,
  agent_id, require_boundary, now) -> None` (upsert).
- SQLite: `CREATE TABLE IF NOT EXISTS` inside `init_sqlite_schema` + a schema
  **version-4** `INSERT OR IGNORE INTO schema_migrations` row (NB the table is
  `schema_migrations`; `get_sqlite_schema_versions` returns a **tuple**). For the
  upsert SQL use the `agent_issuable_scope_bounds` `ON CONFLICT … DO UPDATE` pattern
  as the template (NOT the `subject_tokens` insert). The v4 row breaks every
  existing schema-version assertion — the plan MUST `grep -rn '(1, 2, 3)\|\[1, 2,
  3\]\|schema_version' tests/` and bump them all, not trust a frozen list. Known
  sites: `test_cli.py` (both the `(1,2,3)` tuples AND the **singular**
  `schema_version == 3` → 4), `test_storage_ops.py`, and
  `test_subject_token_repository.py` (its `(1,2,3)` assert + the version-named test
  `test_sqlite_schema_records_version_3`).

### 2. Enforce check — core stays identity-agnostic

- `EnforceInput` (`vinctor_core/models.py`) gains `require_boundary: bool = False`.
- `_resolve_boundary` (`vinctor_core/enforce.py`): currently `boundary_id is None →
  return None`. Change to: if `boundary_id` is None **and** `enforce_input
  .require_boundary` → `_deny(..., "boundary_required", ...)`; otherwise unchanged.
  The unusable branches (`boundary_not_found`/`boundary_inactive`) are untouched.
- **Empty/whitespace header — do NOT normalize to absent.** Today a present-but-
  empty `X-Vinctor-Boundary-Id` is `""` (not `None`) and already fails closed via a
  registry miss → `boundary_not_found`. Leave that untouched: require_boundary only
  converts the *truly-absent* (`None`) case. An empty header therefore keeps denying
  (`boundary_not_found`) with or without the flag — the gap is closed either way and
  the default-off path stays byte-for-byte unchanged. (The ADR 0007 "empty ==
  absent" dogfood note applies to a future `require_subject_token`, where empty
  would otherwise mean "no proof → permit"; it does NOT apply here because an empty
  boundary already denies.)

The core does **not** read any repository — it receives the resolved boolean. The
**service layer** does the per-agent lookup:

- `enforce_v1_contract` (direct) and `delegated_enforce_v1_contract` gain an
  `agent_enforcement_settings_repository` keyword param (default `None`). NB the
  `subject_token_repository` precedent was **delegated-only** — the direct
  `enforce_v1_contract` has never carried a non-grant repo, so this is new plumbing
  on the direct path too. Both contracts share one private helper,
  **`_evaluate_and_record`, the single place that constructs `EnforceInput`** — the
  resolved `require_boundary` bool must flow into that helper. The public functions
  resolve it after the authorized identity is known — direct: `request.(workspace_id,
  agent_id)`; delegated: `(trusted_ws, request.agent_id)` (the validated subject) —
  and pass it down.
- The service methods (`InMemoryV1Service.enforce`/`.delegated_enforce` + the SQLite
  equivalents) pass their `agent_enforcement_settings_repository` field into the
  contract.
- **Fail-open guard (deliberate):** a `None` repo is treated as flag-off (permit) —
  a deliberate, documented fallback so existing call sites compile, not merely
  inherited from the token pattern. Because a *dropped* repo would silently
  un-harden an agent (fail-open) and a flag-OFF test cannot catch that, the wiring is
  pinned by a **flag-ON service test on BOTH the direct and delegated paths** (set
  the flag via the service's own repo, enforce with no boundary, assert deny).

### 3. Caller response + audit

A `boundary_required` denial is an ordinary deny: HTTP 403, generic deny decision,
recorded in the audit trail with reason `boundary_required` (same shape as the
existing boundary denials), no disclosure beyond what a normal deny returns. The
caller-facing contract is otherwise unchanged.

### 4. Backward compatibility

Default off everywhere: `get_require_boundary` returns False with no row, so every
existing enforce (which sets no flag) takes the exact current path. This is the
load-bearing regression guard and gets explicit tests on both the direct and
delegated paths.

### 5. Operator surface — CLI (direct-DB)

A direct-DB operator command (like `operator bounds`, needing `--db` +
`--workspace-id`) to set/unset/show the flag, e.g.
`operator agents require-boundary --agent-id <id> --enable|--disable` and a read
form. (Exact command/verb finalized in the plan, mirroring the existing
`operator bounds` subtree.) Policy-file integration is deferred.

## Testing (TDD)

- **Core:** `_resolve_boundary` — `require_boundary=True` + absent → deny
  `boundary_required`; `require_boundary=True` + usable boundary → proceeds;
  `require_boundary=True` + unusable → its existing reason (unchanged);
  `require_boundary=False` + absent → permit (regression).
- **Empty header (no normalization):** empty/whitespace `boundary_id` denies
  `boundary_not_found` **with the flag OFF** (regression — this path is currently
  untested and must stay a deny, NOT flip to permit) **and with the flag ON** (the
  require check only fires on truly-absent `None`, so empty still hits the
  registry-miss deny). Pin both.
- **Settings repo:** set/get round-trip (InMemory + SQLite), default False for an
  absent row.
- **Service (direct + delegated):** with the flag set via the settings repo and no
  boundary → deny; with a usable boundary → permit; with the flag unset → behavior
  identical to today (regression, both paths).
- **Schema:** v4 recorded; the bumped `(1,2,3,4)` assertions pass; backup/restore/
  info still validate.
- **CLI:** `--enable` → a subsequent enforce without a boundary denies
  `boundary_required`; `--disable` → permits; show reflects state.
- **Audit:** the `boundary_required` deny is recorded with the right reason and
  leaks nothing extra.

## Risks / notes

- **Per-agent only:** an operator hardening a whole workspace must set the flag per
  agent. Acceptable for this slice; workspace-level is the named follow-up.
- **Delegated subject:** for `/v1/enforce/delegated` the flag is keyed on the
  *subject* agent (the one being authorized), not the PEP — consistent with how the
  decision is "about" the subject.
- **disable kill-switch becomes effective** for hardened agents: a disabled boundary
  can no longer be evaded by dropping the header, because absent → deny when
  required.
