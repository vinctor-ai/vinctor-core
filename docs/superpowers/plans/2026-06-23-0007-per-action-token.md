# ADR 0007 hardening C2 — per-action subject-token binding (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Let a subject token be **optionally bound to one `action` + `resource`**
at mint, so a stolen token authorizes only that single operation (not the grant's
full scope) for its TTL. Directly closes the ADR 0007 dogfood residual ("within
TTL a token is a bearer for the grant's full scope"). Stateless; default
(unbound) behavior unchanged.

**Scope note:** This implements the *per-action* half of the deferred
"single-use / per-action" item. True single-use (consume-on-use) is intentionally
**not** built — it is retry-fragile (a response lost after enforce would consume
the token, failing the retry) and replay is already bounded by short TTL +
audience + revocation + (planned) PoP. Per-action binding is the stateless,
non-fragile narrowing.

**Design (locked):**
- **Schema v6:** two nullable columns on `subject_tokens` — `bound_action TEXT`,
  `bound_resource TEXT` — via a migration helper (mirror the C1 helpers) + the
  `CREATE TABLE` body. A binding is an **action+resource pair**: both set or
  neither (validated at mint).
- **Mint:** `POST /v1/tokens` body gains optional `action` + `resource` (both
  non-empty strings, both-or-neither); `vinctor agent token mint` gains optional
  `--action` / `--resource`. Stored on the token.
- **Delegated enforce:** when the token has a binding, the request's `action` /
  `resource` must equal `bound_action` / `bound_resource`, else fail closed with
  the existing `subject_token_invalid` (extend the existing identity-tuple check).

**Invariants:** unbound token (both NULL) → behavior byte-for-byte unchanged
(token still authorizes the grant's scope). Default-off paths untouched. Both-or-
neither binding enforced at mint (400). Bound-mismatch is fail-closed (403, generic
`subject_token_invalid` — no leak of what was bound). Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/0007-per-action-token`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: schema v6 — `bound_action` / `bound_resource` columns

**Files:** `src/vinctor_service/models.py` (SubjectToken), `src/vinctor_service/sqlite.py`;
tests `tests/test_subject_token_repository.py` + schema-version asserts.

- [ ] **Step 1 — failing test:** `get_sqlite_schema_versions(conn) == (1,2,3,4,5,6)`
  (rename version test to `_6`); a SubjectToken round-trip (InMemory + SQLite)
  setting/reading `bound_action`/`bound_resource`.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — record:** add trailing `bound_action: str | None = None` and
  `bound_resource: str | None = None` to the `SubjectToken` frozen dataclass.
- [ ] **Step 4 — sqlite:** add `bound_action TEXT` + `bound_resource TEXT` to the
  `subject_tokens` `CREATE TABLE` body; add a migration helper
  `_ensure_subject_tokens_bound_columns(conn)` (ALTER ADD both, PRAGMA-guarded,
  mirror `_ensure_subject_tokens_revoked_at_column`) wired into
  `init_sqlite_schema`; add the v6 `schema_migrations` row after v5; update
  `SQLiteSubjectTokenRepository.insert`/`get_by_hash`/`get_by_id`/
  `list_subject_tokens` and `_subject_token_from_row` to write/read both columns
  (plain nullable TEXT — `row[N]` / direct value, no datetime helper).
- [ ] **Step 5 — bump asserts:** `grep -rn '(1, 2, 3, 4, 5)\|\[1, 2, 3, 4, 5\]\|schema_version' tests/`
  and bump every non-empty-DB assert to include 6; leave None/[] empty-DB cases.
- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(tokens): schema v6 — subject_tokens.bound_action/bound_resource`.

---

### Task 2: mint binding + delegated bound-check

**Files:** `src/vinctor_service/subject_tokens.py` (mint contract),
`src/vinctor_service/v1_http.py` (`_parse_tokens_body` + `handle_v1_tokens_http` +
`V1TokenService.mint_subject_token`), `src/vinctor_service/in_memory.py` +
`sqlite.py` (service `mint_subject_token` signature), `src/vinctor_service/cli.py`
(mint args), `src/vinctor_service/v1_enforce.py` (delegated check); tests
`tests/test_subject_token_mint.py` + `tests/test_per_action_token.py` (new) +
`tests/test_cli.py`.

- [ ] **Step 1 — failing tests:**
  - **mint (contract/service):** mint with `action="write", resource="repo/x/y"`
    stores `bound_action`/`bound_resource`; mint with only one of them → error
    (both-or-neither).
  - **delegated enforce:** a token bound to `(write, repo/x/y)` presented for that
    exact action/resource → permit (`identity_proven=true`); the SAME token
    presented for a DIFFERENT action or resource (still within the grant) → 403
    `forbidden` + `subject_token_invalid`; an **unbound** token → unchanged (works
    for any action/resource the grant covers).
  - **HTTP/CLI (optional, light):** `POST /v1/tokens` with `action`+`resource` →
    201; with only `action` → 400.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — mint contract.** In `subject_tokens.py` `mint_subject_token`, add
  optional kwargs `bound_action: str | None = None`, `bound_resource: str | None =
  None`; validate both-or-neither (raise `ValueError` if exactly one is set); set
  them on the `SubjectToken(...)`.
- [ ] **Step 4 — service + HTTP + CLI plumb-through.**
  - `V1TokenService.mint_subject_token` (Protocol) + both services'
    `mint_subject_token` gain the two optional kwargs, forwarded to the contract.
  - `_parse_tokens_body`: accept optional `action`/`resource` (non-empty strings if
    present; reject exactly-one-of with 400 `invalid_request`); `handle_v1_tokens_http`
    forwards them to `service.mint_subject_token`.
  - `cli.py` `agent token mint`: add `--action` and `--resource`; include in the
    `POST /v1/tokens` body when provided.
- [ ] **Step 5 — delegated bound-check.** In `v1_enforce.py`, extend the existing
  identity-tuple failure condition (the big `if (...)` at ~line 264) with:
  `or (token.bound_action is not None and token.bound_action != request.action)`
  `or (token.bound_resource is not None and token.bound_resource != request.resource)`.
  Same fail-closed `subject_token_invalid` path (no new reason, no leak).
- [ ] **Step 6 — run tests + full suite + ruff; commit** `feat(tokens): per-action subject-token binding (mint + delegated check)`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement). PR body: per-action binding,
  default-unbound unchanged, single-use deferred (with rationale).

## Notes
- **Unbound = unchanged:** both columns NULL → the new `if` clauses are no-ops →
  the token authorizes the grant's full scope exactly as today. Pin with an
  unbound-token regression test.
- **Both-or-neither:** a binding is a pair; reject a half-binding at mint (400 at
  the HTTP layer, `ValueError` at the contract).
- **No leak:** a bound-mismatch returns the same generic `subject_token_invalid`
  as the other token failures; do not reveal the bound action/resource.
- **Scope:** action/resource validation grammar already happens in the PDP at
  enforce time; mint only stores the strings (it does not need to re-validate scope
  grammar — a token bound to a nonsense action simply never matches → deny).
