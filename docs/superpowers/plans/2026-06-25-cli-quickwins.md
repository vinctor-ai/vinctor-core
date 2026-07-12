# R — CLI UX quick-wins (non-breaking) (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Land the non-breaking CLI UX quick-wins from the convention review. NO
breaking renames/restructures (those "bigger calls" are deferred pending a decision).
Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/cli-quickwins`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. stdlib only
(do NOT add Click/Typer); `ruff check` only; keep ALL existing tests green; all current
invocation forms must keep working (pure additive UX).

---

### Task 1: accept global/output flags AFTER the subcommand (keep pre-role form)

**Problem:** all persistent flags (--db, --endpoint, --workspace-key, --workspace-id,
--agent-id, --agent-key, --grant-ref, --boundary-id, --json, -o/--output) are declared
only on the root parser (cli.py ~95-108), so `vinctor agent enforce -o json` and
`vinctor operator audit list --db x` fail with `unrecognized arguments`; only the
pre-role form works.

**Files:** `src/vinctor_service/cli.py` (`_parser`, `_add_*_commands`); test
`tests/test_cli.py`.

- [ ] **Step 1 — failing tests:** for a representative set, BOTH positions parse to the
  same result: `vinctor -o json agent enforce ...` AND `vinctor agent enforce ... -o json`;
  `vinctor --db X operator audit list` AND `vinctor operator audit list --db X`. Assert
  the trailing form no longer errors and behaves identically to the pre-role form.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement (stdlib argparse parent-parser pattern):** move the
  persistent flags into a shared parent `ArgumentParser(add_help=False)` and pass
  `parents=[global_parser]` to the root AND to every LEAF subparser so the flags are
  accepted at both levels. **CRITICAL argparse gotcha:** a flag defined on both the
  root and a leaf will have the leaf's parse CLOBBER the root-provided value with the
  leaf default when the flag is omitted on the leaf. Prevent this by giving the
  per-leaf copies `default=argparse.SUPPRESS` (so an omitted leaf flag does NOT appear
  in the namespace and cannot overwrite the root value), and keep the real defaults
  (env fallbacks) ONLY on the root copy — OR resolve via a single merge. Verify with
  tests that: (a) flag before role, (b) flag after subcommand, (c) flag in BOTH (leaf
  wins, which is fine), (d) flag in NEITHER (env/default applies) ALL behave correctly.
- [ ] **Step 4 — run tests + full suite + ruff; commit** `feat(cli): accept global/output flags after the subcommand (argparse parent parser)`.

---

### Task 2: `--version` + clean error on a malformed credential (no traceback)

**Files:** `src/vinctor_service/cli.py` (`_parser`, `_request_json` ~1514-1571); test
`tests/test_cli.py`.

- [ ] **Step 1 — failing tests:**
  - `vinctor --version` prints `vinctor <version>` and exits 0 (no `role is required`).
  - an `--agent-key`/`--workspace-key` containing a control char / embedded newline
    yields a clean `CliError` (exit EXIT_AUTH or EXIT_USAGE, one-line `error: ...`, NO
    `Traceback`), instead of an http.client `ValueError: Invalid header value`.
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** add `parser.add_argument("--version", action="version",
  version=f"vinctor {importlib.metadata.version('vinctor-core')}")` on the root parser.
  In `_request_json`, wrap the connection/request construction so `ValueError`/`OSError`
  from http.client become a `CliError` with a one-line message (and a sensible exit
  code); optionally reject control chars in credential values when read.
- [ ] **Step 4 — run tests + full suite + ruff; commit** `feat(cli): add --version; map malformed-credential errors to clean CliError`.

---

### Task 3: help/description text on the command tree + `--json`/`-o` clarification

**Files:** `src/vinctor_service/cli.py` (every `add_parser` + global `add_argument`);
test `tests/test_cli.py`.

- [ ] **Step 1 — failing test:** assert that `--help` for a few representative nodes
  contains real glosses — e.g. `vinctor operator --help` distinguishes the resources;
  `vinctor operator requests --help` distinguishes `inbox` vs `list` and `view` vs
  `timeline` and `approve` vs `evaluate`; `bounds` vs `require-boundary` are
  disambiguated; global flags show their purpose + `VINCTOR_*` env var. (Assert on
  substrings of the captured `--help` output via SystemExit/stdout.)
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:** add a concise `help=`/`description=` to every subparser
  (`add_parser(..., help="...")`) and a `help=` to every global flag
  (`add_argument(..., help="... (env: VINCTOR_X; default: ...)")`). Prioritize the
  ambiguous clusters called out above. In the `-o/--output` + `--json` help, state that
  `--json` is an alias for `-o json` and the precedence (`--json` wins). NO behavior
  change — help text only.
- [ ] **Step 4 — run tests + full suite + ruff; commit** `docs(cli): help text across the command tree + --json/-o alias note`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green; every prior invocation form still works.
- [ ] Update `docs/cli-reference.md` if it warns that `-o json` must precede the role
  (that constraint is now lifted) — fold a one-line update in.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final adversarial
  review per the march agreement).

## Notes
- Deferred "bigger calls" (NOT in this slice, need a decision): unify HTTP-vs-direct-DB
  transport, collapse require-* into an `operator mandate` noun, rename `bounds`,
  reconsider the agent/operator persona split.
- Stay stdlib-only — do NOT introduce Click/Typer.
