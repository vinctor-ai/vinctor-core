# Reject path-traversal (`.`/`..`) segments in resource scopes (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Close a confirmed HIGH authorization bypass: a wildcard grant
`write:repo/feature/*` currently PERMITS `repo/feature/../protected/secrets`
(resolves to `repo/protected/secrets`, an explicitly-forbidden path) because
`_is_valid_resource` accepts `..` as a literal segment and the matcher does a raw
`resource.startswith(prefix)` with no normalization. Fix: reject any resource
segment that is exactly `.` or `..`, fail-closed, at BOTH grant-scope validation
and enforce-request validation. stdlib only; no schema change. Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`fix/scope-path-traversal`, main human-merge-only (controller merges after review).
Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. `ruff check` only.

## Confirmed repro (must turn from PERMIT to blocked)
Grant `write:repo/feature/*`:
- `write repo/feature/../protected/secrets` → currently PERMIT, must be BLOCKED.
- `write repo/feature/../.github/workflows/deploy` → currently PERMIT, must be BLOCKED.
- `write repo/feature/../../etc/passwd` → currently PERMIT, must be BLOCKED.
- `write repo/feature/login` → PERMIT (must stay).
- `write repo/protected/secrets` (direct) → deny (must stay).

## Design decision (founder-approved)
REJECT `.`/`..` segments (do NOT canonicalize). No legitimate resource is named
`.` or `..`, so rejection breaks nothing real and closes the class globally,
fail-closed. (`.`/`..` only as WHOLE segments — names like `orders.api`, `v1.2`
must stay valid.)

---

### Task 1: reject `.`/`..` segments + prove the bypass is closed end-to-end

**Files:**
- Modify: `src/vinctor_core/scope.py` (`_is_valid_resource`).
- Test: `tests/` — the scope unit tests (find the existing `test_scope*.py`) AND a
  service-level enforce test that reproduces the bypass (find the existing
  enforce/e2e test module, e.g. `test_v1_enforce*.py` / `test_in_memory*` that
  drives `InMemoryV1Service` or `evaluate_enforce` with a wildcard grant).

- [ ] **Step 1 — recon:** read `src/vinctor_core/scope.py` fully (`_is_valid_resource`,
  `match_scope`, `_matches_terminal_resource_wildcard`, the segment loop + the
  wildcard branch + `_RESOURCE_SEGMENT_RE`). Trace the ENFORCE path: does it call
  `is_valid_requested_resource(...)` and reject (scope_invalid) BEFORE `match_scope`?
  (grep the enforce evaluation in `policy.py` / the service layer.) This determines
  whether fixing `_is_valid_resource` alone blocks the bypass end-to-end.
- [ ] **Step 2 — failing UNIT tests** (scope tests):
  - `is_valid_requested_resource` returns False for `repo/..`, `repo/feature/..`,
    `repo/feature/../x`, `../repo`, `repo/.`, `repo/./x`, `repo/feature/.` .
  - `is_valid_requested_resource` STILL returns True for legit dotted names:
    `repo/orders.api`, `db/reports.q3`, `a/v1.2/b`, `repo/feature-x/login`.
  - `is_valid_grant_scope` returns False for `write:repo/../*`, `write:repo/./x`,
    `write:repo/feature/../*`; STILL True for `write:repo/feature/*`,
    `read:db/reports.q3/*`.
- [ ] **Step 3 — failing END-TO-END test** (the actual security regression):
  using the same construct the bug was found with (a wildcard grant
  `write:repo/feature/*`), assert that enforcing
  `write repo/feature/../protected/secrets` (and `.../../etc/passwd`) is NOT
  permitted (denied or scope_invalid — anything but permit), while
  `write repo/feature/login` IS permitted and direct `write repo/protected/secrets`
  is denied. Use whatever enforce surface the repo's tests use (core
  `evaluate_policy`/`evaluate_enforce` or `InMemoryV1Service`).
- [ ] **Step 4 — run, expect FAIL** (the e2e test fails today = bug reproduced).
- [ ] **Step 5 — implement:** in `_is_valid_resource`, after the existing segment
  split + empty-segment check, reject any segment equal to `.` or `..` (for BOTH the
  wildcard branch and the non-wildcard branch — a scope like `write:repo/../*` must
  be invalid). Keep `_RESOURCE_SEGMENT_RE` as-is for legit dotted names. If — and
  only if — the recon shows the enforce path can reach `match_scope` WITHOUT first
  validating the requested resource, ALSO reject `.`/`..` in the match path so the
  bypass is closed regardless of call ordering (defense-in-depth). The e2e test in
  Step 3 is the acceptance criterion: the traversal MUST be blocked end-to-end.
- [ ] **Step 6 — run unit + e2e + FULL suite + ruff; commit**
  `fix(security): reject "." / ".." path-traversal segments in resource scopes`.

## Final
- [ ] Full suite + `ruff check src/ tests/` green; the e2e bypass test passes
  (traversal blocked, legit paths still permit).
- [ ] `docs/next-actions.md`: record the fix (path-traversal authz bypass closed).
  If `docs/threat-model.md` or scope docs describe resource grammar, add one line
  that `.`/`..` segments are rejected. Fold into the PR.
- [ ] Controller runs a final adversarial review before merge. Push branch + open PR.

## Invariants
- FAIL-CLOSED: the change only ever REJECTS inputs (turns a wrong permit into a
  block); it must never turn a deny into a permit. Confirm no legit resource regresses.
- Only WHOLE `.`/`..` segments are rejected; dotted names (`orders.api`) stay valid.
- No schema/DB change; stdlib only.
