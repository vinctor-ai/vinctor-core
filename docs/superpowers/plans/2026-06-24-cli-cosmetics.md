# K — LOW cosmetics: enforce -o json single object + policy export round-trip (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Two low-risk cosmetic fixes from the backlog. No schema change.

Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/cli-cosmetics`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: `agent enforce -o json` emits a single JSON object on deny

**Problem (recon):** `_agent` enforce deny branch (`cli.py`) `_emit`s the decision to
stdout then raises `CliError(action_denied, code=EXIT_DENIED)`; `run_vinctor` catches
it and `_emit_error` prints a SECOND JSON object to stderr. In `-o json` mode a deny
→ two JSON objects (stdout decision + stderr error).

**Files:** `src/vinctor_service/cli.py` (`CliError.__init__`, the enforce deny
`raise`, `_emit_error`); test `tests/test_cli.py`.

- [ ] **Step 1 — failing test:** run `agent enforce` against a denying grant with
  `--json` (raw `run_vinctor(stdout, stderr)` pattern, NOT the `_run` helper which
  asserts status 0). Assert: return code `EXIT_DENIED` (4); stdout contains EXACTLY
  one JSON object (the decision, `decision == "deny"`); stderr is empty in JSON mode.
- [ ] **Step 2 — run, expect FAIL** (today stderr has the second JSON object).
- [ ] **Step 3 — implement (preferred minimal):** add an optional `quiet_json: bool
  = False` to `CliError.__init__`; set it `True` ONLY on the enforce-deny raise
  (which already emitted a structured decision on stdout); in `_emit_error`, when in
  JSON mode AND `error.quiet_json`, skip the stderr JSON print. Exit code stays
  `EXIT_DENIED` (4). Text mode still prints `error: action_denied` to stderr.
- [ ] **Step 4 — run test to verify pass.** Confirm NON-enforce CliErrors still emit
  their stderr JSON in JSON mode (they write nothing to stdout, so that is their only
  machine-readable signal) — do NOT suppress those.
- [ ] **Step 5 — commit** `fix(cli): agent enforce -o json emits a single JSON object on deny`.

---

### Task 2: `operator policy export` emits `max_ttl` (round-trip symmetry)

**Problem (recon):** `export_policy_document` (`policy_files.py`) always emits
`max_ttl_seconds: <int>`, but apply input used `max_ttl: "30m"`. apply
(`_parse_rule_entry` / `_duration_seconds`) ACCEPTS BOTH keys (mutually exclusive),
so only export is asymmetric. The stored model only has `max_ttl_seconds` (int), so
literal-string fidelity is impossible without a schema change.

**Files:** `src/vinctor_service/policy_files.py` (the single export line); test
`tests/test_cli.py` (the existing policy round-trip test).

- [ ] **Step 1 — failing/extended test:** assert the exported document's auto-approval
  rule uses the `max_ttl` key (value `"<N>s"`), and that re-applying the exported
  file is idempotent (`rules_updated == 1`, `rules_created == 0`) and yields the same
  `max_ttl_seconds` in the DB (e.g. 1800).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** change the export line from `"max_ttl_seconds":
  rule.max_ttl_seconds` to `"max_ttl": f"{rule.max_ttl_seconds}s"` (a STRING so
  `_duration_seconds`' `isinstance(raw, str)` path accepts it on re-apply). Emit
  exactly ONE of the two keys (apply rejects both) — so do NOT also emit
  `max_ttl_seconds`. apply still accepts the legacy `max_ttl_seconds` key for anyone
  who wrote it explicitly, so nothing breaks.
- [ ] **Step 4 — run test to verify pass + full suite + ruff; commit** `fix(policy): export emits max_ttl matching the input key for symmetric round-trip`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Update `docs/next-actions.md` (remove these two from Low-priority cosmetics /
  mark fixed). Fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- FIX 1: do NOT change the exit code (4) — only suppress the JSON-mode stderr line
  for the deny case; scope the suppression to the enforce-deny via the per-CliError
  flag (never blanket-suppress all CliErrors).
- FIX 2: apply rejects setting BOTH `max_ttl` and `max_ttl_seconds`; export must emit
  exactly one. The `f"{n}s"` form is always a valid, unambiguous duration string.
