# ADR 0007 hardening C1 — token revoke + require_subject_token (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Two deferred ADR 0007 follow-ups: (1) **explicit subject-token
revocation** (invalidate a minted token before its TTL); (2) **`require_subject_token`**
— an opt-in flag (mirroring `require_boundary`) that makes a delegated enforce for
a hardened subject *require* a valid subject token (mandate proven identity),
treating an empty/whitespace token header as absent → deny.

**Design (locked):**
- **Schema v5** (two additive columns, via `ALTER … ADD COLUMN` migration helpers
  mirroring `_ensure_scope_bounds_max_ttl_column`, plus the `CREATE TABLE` bodies):
  `subject_tokens.revoked_at TEXT` (nullable) and
  `agent_enforcement_settings.require_subject_token INTEGER NOT NULL DEFAULT 0`.
- **Revoke:** a revoked token (`revoked_at` not null) fails closed on the delegated
  proven path (same `subject_token_invalid` reason). Operator surface:
  `operator tokens revoke <token_id>` + `operator tokens list` (direct-DB).
- **require_subject_token:** mirror `require_boundary` exactly — ws-default +
  per-agent override resolution on the settings repo; the delegated contract, when
  `is_subject_token_required(trusted_ws, subject)` is True and no **usable** token
  is presented (`subject_token` is None OR empty/whitespace), fails closed with a
  **new** reason `subject_token_required`. Operator CLI
  `operator require-subject-token enable|disable|show [--workspace]`.

**Invariants:** default-off byte-for-byte unchanged (no flag → no mandate; no
revoked_at → unchanged). The mandate check runs BEFORE the existing optional-token
block. Empty/whitespace token == absent for the mandate. Revoked check is inside
the existing token block, fail-closed (403, never 503/legacy-fallback). Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/0007-require-token-revoke`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: schema v5 — `revoked_at` + `require_subject_token` columns

**Files:** `src/vinctor_service/sqlite.py`, `src/vinctor_service/models.py` (the
`SubjectToken` record), test `tests/test_subject_token_repository.py` + the
schema-version assertions.

- [ ] **Step 1 — failing test** (`tests/test_subject_token_repository.py`): assert
  `get_sqlite_schema_versions(conn) == (1, 2, 3, 4, 5)` (rename the version test to
  `_5`); and a SubjectToken round-trip that sets/reads `revoked_at`.

- [ ] **Step 2 — run, expect FAIL.**

- [ ] **Step 3 — `SubjectToken.revoked_at`.** In `src/vinctor_service/models.py`,
  add a trailing field `revoked_at: datetime | None = None` to the `SubjectToken`
  frozen dataclass.

- [ ] **Step 4 — SQLite schema.** In `sqlite.py`:
  - Add `revoked_at TEXT` to the `subject_tokens` `CREATE TABLE` body and
    `require_subject_token INTEGER NOT NULL DEFAULT 0` to the
    `agent_enforcement_settings` `CREATE TABLE` body.
  - Add two migration helpers (mirror `_ensure_scope_bounds_max_ttl_column`):
    `_ensure_subject_tokens_revoked_at_column(conn)` (ALTER add `revoked_at TEXT`)
    and `_ensure_agent_enforcement_require_subject_token_column(conn)` (ALTER add
    `require_subject_token INTEGER NOT NULL DEFAULT 0`); call both from
    `init_sqlite_schema` next to the existing `_ensure_*` calls.
  - Add a version-5 `INSERT OR IGNORE INTO schema_migrations VALUES (5, …)` row
    after the v4 row, before `conn.commit()`.
  - Update `SQLiteSubjectTokenRepository.insert`/`get_by_hash` + `_subject_token_from_row`
    to write/read `revoked_at` (use the nullable-datetime helpers
    `_datetime_to_storage`/`_datetime_from_storage`, NOT bare `.isoformat()`, since
    it is nullable).

- [ ] **Step 5 — bump schema-version asserts.** `grep -rn '(1, 2, 3, 4)\|\[1, 2,
  3, 4\]\|schema_version' tests/` and bump every non-empty-DB assertion to include
  5 (`(1,2,3,4,5)` / `[1,2,3,4,5]` / `schema_version == 5`); leave the empty-DB
  `None`/`[]` cases. Update `InMemorySubjectTokenRepository` to accept/return
  `revoked_at` (the record now has the field; default None).

- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(tokens): schema v5 — subject_tokens.revoked_at + agent_enforcement_settings.require_subject_token`.

---

### Task 2: token revoke (repo + delegated check + CLI)

**Files:** `src/vinctor_service/repositories.py`, `sqlite.py`,
`src/vinctor_service/v1_enforce.py`, `src/vinctor_service/cli.py`; tests
`tests/test_require_boundary.py`-style new `tests/test_subject_token_revoke.py` +
`tests/test_cli.py`.

- [ ] **Step 1 — failing tests:** (a) at the contract level, a delegated proven
  enforce with a **revoked** token → 403 `forbidden` + `subject_token_invalid`
  rejection audit (mirror `tests/test_delegated_enforce_contract.py` token tests,
  but `repo`-insert a token whose `revoked_at` is set); (b) CLI: mint a token (live
  service), `operator tokens list` shows it, `operator tokens revoke <token_id>`
  marks it revoked, a subsequent delegated enforce denies.

- [ ] **Step 2 — run, expect FAIL.**

- [ ] **Step 3 — repo.** Add to `SubjectTokenRepository` (Protocol + InMemory +
  SQLite): `get_by_id(token_id) -> SubjectToken | None`,
  `revoke(token_id, *, now) -> bool` (set `revoked_at`, return False if missing),
  and `list_subject_tokens(workspace_id) -> tuple[SubjectToken, ...]` (for the CLI
  list; ordered by issued_at). SQLite uses `UPDATE subject_tokens SET revoked_at =
  ? WHERE token_id = ?`.

- [ ] **Step 4 — delegated check.** In `v1_enforce.py`, inside the existing token
  block, **after** `if token is None: …` and **before** the audience/identity-tuple
  check, add: `if token.revoked_at is not None:` → `_record_rejection(reason_code=
  REASON_SUBJECT_TOKEN_INVALID, …)` + `return _pre_audit_error(403, "forbidden",
  "subject token is not valid")`. (Revoked == invalid; same fail-closed path.)

- [ ] **Step 5 — CLI.** Add an `operator tokens` resource (mirror `operator
  bounds`): `revoke <token_id>` (calls `service.subject_token_repository.revoke`;
  emit `{token_id, revoked: true|false}`; `CliError` if not found) and `list`
  (emit masked rows: `token_id, agent_id, grant_ref, audience, expires_at,
  revoked` — never the hash/raw). Register under `_add_operator_commands`; dispatch
  in `_operator`.

- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(tokens): explicit subject-token revocation (operator tokens revoke/list)`.

---

### Task 3: `require_subject_token` mandate (mirror require_boundary)

**Files:** `src/vinctor_service/repositories.py`, `sqlite.py`,
`src/vinctor_service/v1_enforce.py`, `src/vinctor_core/audit.py`,
`src/vinctor_service/cli.py`, `src/vinctor_service/policy_files.py` (optional
parity); tests `tests/test_require_subject_token.py` + `tests/test_cli.py`.

- [ ] **Step 1 — failing tests** (delegated path):
  - hardened subject (`require_subject_token` set) + **no** `X-Subject-Token` → 403
    `forbidden` + a `subject_token_required` rejection audit.
  - hardened subject + **empty/whitespace** token → same deny (empty == absent).
  - hardened subject + a **valid** token → permit (`identity_proven=true`).
  - unhardened subject + no token → legacy permit (regression).

- [ ] **Step 2 — run, expect FAIL.**

- [ ] **Step 3 — settings repo.** Mirror the `require_boundary` methods for
  `require_subject_token`: `get_require_subject_token_setting(ws, agent) -> bool |
  None`, `is_subject_token_required(ws, agent) -> bool` (agent row → ws-default
  `agent_id=""` → False), `set_require_subject_token(ws, agent, value, now)` (UPSERT
  the `require_subject_token` column). Add to Protocol + InMemory + SQLite. (The
  InMemory store can hold a second dict keyed `(ws, agent)`; SQLite upserts the
  column, leaving `require_boundary` untouched via `ON CONFLICT … DO UPDATE SET
  require_subject_token = excluded.require_subject_token, updated_at = …`.)

- [ ] **Step 4 — reason code.** In `src/vinctor_core/audit.py`, add
  `REASON_SUBJECT_TOKEN_REQUIRED = "subject_token_required"` beside
  `REASON_SUBJECT_TOKEN_INVALID`.

- [ ] **Step 5 — delegated mandate.** In `delegated_enforce_v1_contract`, after the
  grant-ownership check and **before** the optional-token block, add: resolve
  `required = (agent_enforcement_settings_repository.is_subject_token_required(
  workspace_id=trusted_ws, agent_id=request.agent_id) if …repository is not None
  else False)`. If `required` and the presented token is absent or blank
  (`request.subject_token is None or request.subject_token.strip() == ""`):
  `_record_rejection(reason_code=REASON_SUBJECT_TOKEN_REQUIRED, …)` +
  `return _pre_audit_error(403, "forbidden", "a subject token is required")`. (Then
  the existing optional-token block proves the presented token as today.)

- [ ] **Step 6 — CLI.** Add `operator require-subject-token enable|disable|show
  [--workspace]`, a verbatim mirror of `operator require-boundary` (positional
  `target_agent_id`, `--workspace` for the `agent_id=""` default, `_emit` body with
  `scope`). Register + dispatch.

- [ ] **Step 7 — run tests + full suite + ruff; commit** `feat(tokens): require_subject_token mandate (mirror require_boundary)`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Push branch, open PR (no merge; the controller auto-merges after a final
  adversarial review per the march agreement). PR body covers revoke + the mandate
  + default-off unchanged + the empty==absent rule.

## Notes
- **Default-off:** no `require_subject_token` row and no `revoked_at` → behavior is
  byte-for-byte the current ADR 0007 path. Keep all existing subject-token tests
  green.
- **Empty == absent (mandate):** unlike the *optional* token block (where the
  subject_token header drives the proven path), the mandate must treat a blank
  token header as "no token" → deny. `request.subject_token.strip() == ""` counts
  as absent.
- **Revoked == invalid:** the revoked check returns the SAME generic
  `subject_token_invalid` fail-closed result; do not leak that the token merely
  expired vs was revoked.
- Mandate fires only on the **delegated** path (subject tokens are a delegated-path
  concept); the direct `/v1/enforce` path is unaffected.
