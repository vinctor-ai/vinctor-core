# I — `require_pop` operator mandate (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Add a third opt-in, operator-controlled enforcement mandate `require_pop`
to `agent_enforcement_settings`, mirroring `require_subject_token` /
`require_boundary`. When set for a (workspace, agent), a delegated `/v1/enforce`
whose **resolved subject token is not proof-of-possession bound** (`token.pop_secret
is None`) fails closed. Default off → backward-compatible.

**Semantics (LOCKED — single-purpose, composes with `require_subject_token`):**
`require_pop` denies a *presented* non-PoP token. It does NOT imply
`require_subject_token`: the "no subject token at all" case stays governed by
`require_subject_token`. An operator wanting "must present a PoP-bound token" enables
BOTH flags. This keeps each flag single-purpose and consistent with the existing two
mandates. The deny is the SAME leak-free generic `403 forbidden` external response as
the other token denies; only the audit `reason_code` (`pop_required`) distinguishes
it.

**Why this is the natural complement:** today a PoP token forces a proof
(`v1_enforce.py` PoP-proof block), but an operator cannot force agents to USE PoP
tokens — a non-PoP token sails past the proof block (`pop_secret is None`).
`require_pop` is exactly what catches that.

**Invariants:** default-off byte-for-byte unchanged (no-row → False). Tenant
isolation: the mandate is read with `trusted_ws` (never `request.workspace_id`),
matching the other two mandates. Generic external response (no leak that PoP was the
missing piece). Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv
`.venv/bin/...`, branch `feat/require-pop-mandate`, main human-merge-only. Commit
trailer ends with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: schema + repository (`require_pop` column + accessors)

**Files:** `src/vinctor_service/sqlite.py` (CREATE TABLE column + migration helper +
schema_migrations row + SQLiteAgentEnforcementSettingsRepository methods),
`src/vinctor_service/repositories.py` (Protocol + InMemory impl); tests
`tests/test_agent_enforcement_settings_repository.py`, `tests/test_require_subject_token.py`
(mirror the no-clobber test), and the schema-version assertions across
`tests/test_cli.py` / `tests/test_storage_ops.py` / `tests/test_subject_token_repository.py`.

- [ ] **Step 1 — VERIFY current schema version:** grep `schema_migrations` /
  `get_sqlite_schema_versions` and the test asserts. The current max is **7**; this
  arc adds **8**. (If main has already moved past 7, use `max+1` and adjust every
  assertion accordingly.)
- [ ] **Step 2 — failing tests:** `set_require_pop(workspace_id, agent_id, True)`
  then `is_pop_required(...)` → True; default (no row) → False; the agent→workspace
  (`""`)→False fallback resolution matches `is_subject_token_required`; a no-clobber
  test (set require_pop does NOT null out require_boundary / require_subject_token on
  the same row — mirror `test_require_subject_token.py` no-clobber); and the schema
  version list is now `(1,2,3,4,5,6,7,8)`.
- [ ] **Step 3 — run, expect FAIL.**
- [ ] **Step 4 — schema:** add `require_pop INTEGER NOT NULL DEFAULT 0` to the
  `agent_enforcement_settings` CREATE TABLE; add
  `_ensure_agent_enforcement_require_pop_column` (mirror the existing
  `_ensure_agent_enforcement_*_column` helpers) and call it where the others are
  called; add the `(8, ...)` `INSERT OR IGNORE INTO schema_migrations` row after the
  v7 block.
- [ ] **Step 5 — repository:** add `get_require_pop_setting` (nullable) /
  `is_pop_required` / `set_require_pop` to the `AgentEnforcementSettingsRepository`
  Protocol, the InMemory impl, and the SQLite impl. The SQLite `set_require_pop`
  UPSERT MUST use the no-clobber pattern (INSERT only `(workspace_id, agent_id,
  require_pop, updated_at)` + `ON CONFLICT DO UPDATE SET require_pop=
  excluded.require_pop, updated_at=excluded.updated_at`) so it cannot null the other
  two flags. `is_pop_required` uses the same agent→workspace(`""`)→False fallback as
  `is_subject_token_required`.
- [ ] **Step 6 — bump EVERY schema-version assertion** to include 8. Grep BOTH
  `1, 2, 3, 4, 5, 6, 7` AND `== 7` across the 4 test files; leave the empty-DB
  `None`/`[]` cases alone.
- [ ] **Step 7 — run tests + full suite + ruff; commit** `feat(enforce): require_pop setting — schema + repository`.

---

### Task 2: delegated enforce deny + reason code

**Files:** `src/vinctor_core/audit.py` (`REASON_POP_REQUIRED`),
`src/vinctor_service/v1_enforce.py` (mandate read + deny slot); tests
`tests/test_delegated_enforce_contract.py` (or the existing delegated PoP test file).

- [ ] **Step 1 — failing tests** (delegated contract, both InMemory + a SQLite-backed
  path if the existing PoP tests use one):
  - require_pop ON + subject token WITHOUT `pop_secret` (non-PoP token, valid
    otherwise) → deny `403`, external `error == "forbidden"`, audited with
    `reason_code == "pop_required"`, `identity_proven` NOT set true.
  - require_pop ON + subject token WITH `pop_secret` + valid proof → permit
    (unchanged).
  - require_pop OFF (default) + non-PoP token → unchanged (permit on grant scope).
  - require_pop ON + NO subject token → governed by `require_subject_token`, NOT by
    `require_pop` (i.e. require_pop alone does not deny a missing token; if
    require_subject_token is off, the no-token path is unchanged).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — reason code:** add `REASON_POP_REQUIRED = "pop_required"` to
  `src/vinctor_core/audit.py` next to `REASON_SUBJECT_TOKEN_REQUIRED`.
- [ ] **Step 4 — mandate read:** in `delegated_enforce_v1_contract`, read
  `is_pop_required = agent_enforcement_settings_repository.is_pop_required(
  workspace_id=trusted_ws, agent_id=request.agent_id) if
  agent_enforcement_settings_repository is not None else False` (mirror the
  `is_subject_token_required` / `require_boundary` reads; use `trusted_ws`).
- [ ] **Step 5 — deny slot:** inside the `if request.subject_token is not None:`
  block, AFTER the existing PoP-proof block and BEFORE `identity_proven = True`, add:
  if `is_pop_required and token.pop_secret is None:` → record the rejection
  (`reason_code=REASON_POP_REQUIRED`) and return the generic `_pre_audit_error(403,
  "forbidden", "subject token must be proof-of-possession bound")` — matching the
  exact leak-free shape of the other token denies (external error stays `forbidden`;
  only the audit reason_code differs). Use the explicit `is None` identity check (NOT
  `not token.pop_secret`).
- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(enforce): require_pop deny on non-PoP subject token`.

---

### Task 3: `operator require-pop` CLI

**Files:** `src/vinctor_service/cli.py` (subparser + dispatch + handler); test
`tests/test_cli.py`.

- [ ] **Step 1 — failing test:** `operator require-pop enable --workspace-id W
  --agent-id A` then `... show ...` reports enabled; `disable` flips it; mirrors the
  `operator require-subject-token` tests (direct-DB, needs `--db`).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** add an `operator require-pop {enable,disable,show}`
  subparser (mirror `operator require-subject-token`), a dispatch branch, and a
  `_operator_require_pop` handler reading `args.workspace_id` / `args.agent_id` and
  calling `set_require_pop` / `get_require_pop_setting` on the SQLite repo
  (direct-DB, like the sibling mandates).
- [ ] **Step 4 — run tests + full suite + ruff; commit** `feat(cli): operator require-pop enable/disable/show`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Update `docs/next-actions.md` (require_pop shipped — the third opt-in mandate;
  note it composes with require_subject_token) and the operator-facing docs that list
  the mandates (e.g. `docs/cli-reference.md` / agents-and-grants, if they enumerate
  require-boundary / require-subject-token). Fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- Mint side unchanged: a PoP token is created via `vinctor agent token mint --pop`
  (sets `pop_secret`). `require_pop` is purely operator-side.
- The PoP-proof block already covers "PoP token present but bad proof". `require_pop`
  is orthogonal — it forces the token to BE a PoP token.
- Generic external response is mandatory: the deny must look identical to the other
  token denies (`error == "forbidden"`); the only distinguishing signal is the
  operator-only audit `reason_code`.
