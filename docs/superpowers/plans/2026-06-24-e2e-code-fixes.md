# M — cold-e2e code-bug fixes (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Fix the real code bugs found by the cold end-to-end validation (the
enforcement core was solid; these are CLI/contract polish). Docs drift is handled
separately (arc N).

Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/e2e-code-fixes`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Keep ALL
existing tests green; stdlib only; `ruff check` only.

---

### Task 1: `vinctor-mcp-server` clean `--help` + config-error (no raw traceback)

**Problem:** `vinctor_mcp_server.server.main()` calls `create_stdio_server()` →
`load_config()` before parsing argv, so EVERY invocation (incl. `--help`) raises an
unhandled traceback — `ValueError: VINCTOR_MCP_ENDPOINT is required` when env is
unset, or a `RuntimeError` (MCP SDK missing) — exposing internal paths. A new user
who tries `vinctor-mcp-server --help` gets a stacktrace.

**Files:** `src/vinctor_mcp_server/server.py` (`main`); test
`tests/test_mcp_server.py` (or a new `tests/test_mcp_server_cli.py`).

- [ ] **Step 1 — failing tests:**
  - `main(["--help"])` (or invoking with `--help`) exits 0 and prints usage to
    stdout WITHOUT raising / without a traceback.
  - with `VINCTOR_MCP_ENDPOINT` unset, `main([])` exits NONZERO printing a single
    clean line to stderr (e.g. `error: VINCTOR_MCP_ENDPOINT is required`) and NO
    traceback / no `Traceback (most recent call last)`.
  (Drive `main` with an args list + capture stdout/stderr + `pytest.raises(SystemExit)`
  asserting the code; mirror how the `vinctor` CLI tests assert clean errors.)
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** give `main(argv=None)` an `argparse.ArgumentParser`
  (prog `vinctor-mcp-server`, a short description, `--version` if a version is
  readily available) that parses `argv` FIRST so `--help`/`--version` short-circuit
  before any `load_config()`. Then wrap `create_stdio_server()` (the `load_config()`
  call) in a `try` that catches the config `ValueError` (and the MCP-SDK
  `RuntimeError`) and prints `error: <message>` to `sys.stderr` + `raise SystemExit(<nonzero>)`
  — mirror the clean one-line style the `vinctor` CLI already uses (no traceback).
  The happy path (env set + SDK present) must still run the stdio server unchanged.
- [ ] **Step 4 — run tests + full suite + ruff; commit** `fix(mcp-server): clean --help and config-error handling (no raw traceback)`.

---

### Task 2: align approval-path out-of-bounds status code to 403 (match direct + ADR 0008)

**Problem:** out-of-bounds issuance returns **403** on the direct path
(`grant_http.py:167`, ADR 0008) but **409** on the approval paths
(`grant_request_http.py:339` auto-approve, `:386` approve/reject) for the SAME
error (`scope_outside_issuable_bounds` / `ttl_exceeds_issuable_max` /
`issuable_bounds_not_found`). Same error → different status across paths.

**Files:** `src/vinctor_service/grant_request_http.py` (`_decide_grant_request`,
`_auto_approve_grant_request`); test `tests/` (the grant-request HTTP/contract test).

- [ ] **Step 1 — VERIFY the exact failure `reason` strings** the approve / reject /
  auto-approve service results can return (read `grants.py` / `grant_requests.py`),
  and the direct path's `_BAD_REQUEST_REASONS` set (`grant_http.py`).
- [ ] **Step 2 — failing tests:** approve (and auto-approve) of a request whose
  scopes exceed issuable bounds returns **403** `scope_outside_issuable_bounds`
  (currently 409), matching the direct `POST /v1/grants`; `grant_request_not_pending`
  still returns **409**; `grant_request_not_found` still **404**; any bad-request /
  validation reason returns **400**.
- [ ] **Step 3 — run, expect FAIL.**
- [ ] **Step 4 — implement:** replace the flat `404 ... else 409` (line 386) and the
  auto-approve `return _error(409, ...)` (line 339) with a reason→status mapping:
  `grant_request_not_found`→404; `grant_request_not_pending`→409 (genuine state
  conflict, keep); bad-request/validation reasons→400; the issuable-bounds reasons
  (`scope_outside_issuable_bounds`, `ttl_exceeds_issuable_max`,
  `issuable_bounds_not_found`)→403. Factor a small shared helper (or reuse the
  direct path's reason set) so the two paths and the direct path agree. Do NOT
  change the success paths or the no-matching-rule 200 branch.
- [ ] **Step 5 — run tests + full suite + ruff; commit** `fix(grant-requests): out-of-bounds issuance returns 403 on the approval path (match direct + ADR 0008)`.

---

### Task 3: CLI display fixes — inbox `metadata=` prefix + stale routing on decided requests

**Files:** `src/vinctor_service/cli.py` (the `operator requests inbox` renderer +
the `operator requests view` renderer); test `tests/test_cli.py`.

- [ ] **Step 1 — failing tests:**
  - `operator requests inbox` text output does NOT contain the doubled literal
    `metadata=metadata=` (the value already carries the `metadata=` prefix, or the
    column label adds it — pick one, not both).
  - `operator requests view` of an ALREADY-DECIDED request (status `approved` /
    `rejected`) does NOT present a live-looking `routing=pending_review` /
    `queue_reason=...` as if the request were still awaiting routing (status is
    authoritative). (Either omit routing for decided requests or label it
    creation-time — choose the minimal clear fix and assert it.)
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement** both minimal display fixes in the respective renderers.
  Do not change the JSON output shape (only the text rendering) unless the JSON also
  carries the doubled prefix.
- [ ] **Step 4 — run tests + full suite + ruff; commit** `fix(cli): drop doubled metadata= prefix in inbox; don't show stale routing on decided requests`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement). Doc updates that DESCRIBE these
  behaviors (api-contract / OpenAPI status codes) are handled in arc N.

## Notes
- M5 (token-deny `reason_code`) from the validation was a FALSE POSITIVE: the denies
  DO set `reason_code` in the audit event (`v1_enforce.py` `_record_rejection`); the
  HTTP response intentionally carries only `error`+`reason`. No change.
- The require_pop external `reason` string naming the mandate is acceptable
  (error=="forbidden" is uniform, `subject_token_invalid` stays generic). Plan/ADR
  wording reconciliation is an arc-N doc task, not a code change.
