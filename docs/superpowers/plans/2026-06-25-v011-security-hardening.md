# v0.1.1 security hardening (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** The v0.1.1 security follow-ups deferred from the audit: audit-query SQL
pushdown (no more full-table scan), PoP replay per-token partition (one tenant can't
lock out others), and build-time SBOM/provenance + image HEALTHCHECK. All fail-closed;
keep ALL existing tests green. Repo `/Users/taeheon/dev/agent-authority/vinctor-core`,
venv `.venv/bin/...`, branch `feat/v0.1.1-security-hardening`, main human-merge-only.
Commit trailer ends with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.
stdlib only; `ruff check` only.

---

### Task 1: audit list/export SQL pushdown (kill the full-table scan)

**Problem (from the audit, MEDIUM):** `handle_v1_audit_events_http` reads the WHOLE
`audit_events` table (`service.audit_events`) and json.loads + filters/limits in Python
per request → O(total rows) CPU+memory regardless of `limit`; a cross-tenant DoS lever.

**Files:** the `AuditReadService` protocol + `audit_http.py`; the SQLite + InMemory
audit read impls (`sqlite.py` `SQLiteAuditWriter`/read path, `in_memory.py`); the CLI
`operator audit export` path in `cli.py`; schema (an index); tests.

- [ ] **Step 1 — VERIFY current schema max version** (grep `schema_migrations` inserts;
  it is **9**; this arc adds **10** for the index — adjust every schema-version test
  assertion). Read `audit_http.py` `_parse_filters`/`_event_matches` to mirror the
  EXACT current filter semantics (event_type, grant_ref, boundary_id, agent_id,
  request_id, limit 1..100) so behavior is unchanged.
- [ ] **Step 2 — failing tests:** a new `list_filtered(workspace_id, *, event_type=None,
  grant_ref=None, boundary_id=None, agent_id=None, request_id=None, limit=...)` on the
  audit read service returns the SAME results the current Python-side filter produces
  (same ordering — most-recent-first — and same `limit` clamp), on BOTH the InMemory and
  SQLite impls; the SQLite impl issues a parameterized `SELECT ... WHERE workspace_id=? [AND ...]
  ORDER BY rowid DESC LIMIT ?` (assert it does NOT load the whole table — e.g. via a
  spy/large-table test that only `limit` rows are materialized). Workspace scoping is
  mandatory (never cross-tenant). Schema version list now includes 10.
- [ ] **Step 3 — run, expect FAIL.**
- [ ] **Step 4 — implement:** add `list_filtered(...)` to the `AuditReadService`
  protocol; InMemory does the existing in-memory filter; SQLite issues the parameterized
  WHERE/ORDER/LIMIT (all filters optional, all parameterized — NO string interpolation
  into SQL). Add an index `CREATE INDEX IF NOT EXISTS idx_audit_events_workspace ON
  audit_events(workspace_id)` (or `(workspace_id, rowid)`) in `init_sqlite_schema` + the
  `(10, ...)` schema_migrations row. Switch `handle_v1_audit_events_http` and the CLI
  `operator audit export` to call `list_filtered(...)` instead of reading the full table
  + Python filter. Keep `get_audit_event(event_id)` (single) workspace-scoped as today.
- [ ] **Step 5 — run tests + full suite + ruff; commit** `fix(security): push audit list/export filtering into SQL (workspace-scoped WHERE/LIMIT + index)`.

---

### Task 2: PoP replay store — per-token partition (no cross-tenant lockout)

**Problem (from the audit, MEDIUM):** `SQLiteReplayStore` has a single global
`max_entries` (10000) fail-closed cap; one principal with a valid `pop_secret` can mint
unlimited distinct `(token_id, nonce)` proofs and saturate the global cap, after which
EVERY other tenant's fresh proof is rejected (cross-workspace DoS on the require_pop path).

**Files:** `src/vinctor_service/sqlite.py` (`SQLiteReplayStore.check_and_record`);
`src/vinctor_service/pop.py` (read the in-memory `PopReplayCache` contract — keep it the
reference; decide whether to mirror the per-token cap there too for parity); tests
`tests/test_pop.py` / `tests/test_durable_pop_cache.py`.

- [ ] **Step 1 — failing tests:**
  - token A floods its own `(A, nonce_i)` up to/over a per-token cap; a FRESH proof for
    a DIFFERENT token B is still accepted (no cross-token lockout) — this fails today.
  - replay is still detected within a token (same `(token_id, nonce)` → False).
  - per-token fail-closed: when token A is at its own cap, A's NEW nonce evicts A's own
    oldest within-window nonce (or is rejected) — but NEVER evicts another token's row;
    the record-after-pass + prune + freshness semantics are preserved.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** in `check_and_record`, enforce a per-`token_id` row cap (a
  sensible default, e.g. `max_per_token`) IN ADDITION to (or instead of) the global cap:
  after prune + replay-check, count rows for THIS `token_id`; if at the per-token cap,
  evict that token's own oldest within-window nonce (DELETE the min-ts row for this
  token_id) before inserting — so one token can never exhaust capacity against others.
  Keep the global cap as a generous backstop only. Preserve: record only after mac+
  freshness pass (do not move writes earlier), proof-ts stored value, atomic insert +
  IntegrityError=replay. Keep `in_memory.py` `PopReplayCache` correct (mirror the
  per-token behavior if cheap, else leave a note — the SQLite path is the live one).
- [ ] **Step 4 — run tests + full suite + ruff; commit** `fix(security): partition PoP replay capacity per token_id (no cross-tenant lockout)`.

---

### Task 3: build-time SBOM + provenance + image HEALTHCHECK

**Files:** `.github/workflows/release.yml` (the `docker/build-push-action` step),
`Dockerfile`. Config — validate, do not break.

- [ ] **Step 1 — release.yml:** add `provenance: true` and `sbom: true` to the
  `with:` of the `docker/build-push-action@<sha>` step (keep the existing pin + tags +
  `push:` condition). Validate the YAML parses.
- [ ] **Step 2 — Dockerfile:** add a `HEALTHCHECK` that probes the service health
  endpoint (e.g. `HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD
  python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('VINCTOR_PORT','8765')+'/healthz').read()"`
  or a curl-based probe if curl is present — prefer the stdlib python probe since the
  image is python-slim). Keep the non-root USER + CMD intact.
- [ ] **Step 3 — validate** (yaml parses; full suite + ruff still green — config doesn't
  affect tests) and commit `chore(security): SBOM + provenance on the release image + a HEALTHCHECK`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green; YAML parses.
- [ ] Update `docs/next-actions.md` (move audit-SQL-pushdown + PoP-per-token-partition +
  SBOM/provenance/HEALTHCHECK from the v0.1.1 deferred list to shipped) + `docs/threat-model.md`
  if it referenced the full-table-scan / global-PoP-cap gaps. Fold into the PR.
- [ ] Push branch, open PR. **Do NOT merge** — the founder reviews + merges. (Controller
  will run a final adversarial review before handing it over.)

## Notes
- Fail-closed everywhere; no change may turn a deny/error into a permit.
- Task 1 must preserve the EXACT current filter + ordering + limit semantics — it is a
  performance/isolation refactor, not a behavior change (except removing the full scan).
- Task 2 must keep replay detection intact; only the cross-token capacity coupling changes.
