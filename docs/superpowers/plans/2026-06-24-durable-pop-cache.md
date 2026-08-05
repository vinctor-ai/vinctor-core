# J — durable/shared PoP replay cache (SQLite) (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Make the PoP anti-replay cache durable across restart and correct across
processes by adding a SQLite-backed replay store that drops in behind the existing
`check_and_record` interface. The in-memory `PopReplayCache` stays for tests /
in-memory mode. Closes the residual replay window today: a per-process cache loses
its state on restart (a proof captured within the last `skew` seconds before a
restart could be replayed in the `skew` seconds after).

**Design (locked, from recon):**
- New table `pop_replay_nonces(token_id TEXT NOT NULL, nonce TEXT NOT NULL, ts
  INTEGER NOT NULL, PRIMARY KEY (token_id, nonce))`.
- `SQLiteReplayStore` implements the EXACT `PopReplayCache` method signature
  `check_and_record(self, *, token_id, nonce, ts, now_unix, skew) -> bool` (True =
  first-seen/recorded, False = replay OR fail-closed-when-full). Under a
  `threading.Lock` + one transaction: **prune** (`DELETE ... WHERE ts < now_unix -
  skew`); **replay check** (existing `(token_id, nonce)` → False); **fail-closed
  when full** (`COUNT(*) >= max_entries` → False, do NOT evict a fresh row);
  else **atomic insert** (`INSERT`, catch `sqlite3.IntegrityError` → False as a
  concurrent-insert/cross-process replay) → True. Store the **proof `ts`** (not
  `now`), matching the in-memory value, so the prune cutoff behaves identically.
- Wire ONLY into `SQLiteV1Service.__post_init__` (swap `self._pop_replay =
  PopReplayCache()` → `SQLiteReplayStore(self.conn, ...)`). `in_memory.py` stays
  `PopReplayCache()`. `verify_pop` is duck-typed on `check_and_record`, so no other
  change.

**Invariants:** the durable store NEVER writes on a bad/stale proof (it stays behind
`check_and_record`, which `verify_pop` calls only after `hmac.compare_digest` + the
skew window pass — do not move any DB write earlier). The stored value is the proof
`ts`, the dedup key is `(token_id, nonce)`, the mac is never persisted.
fail-closed-when-full is a TESTED behavior, not an optimization. Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/durable-pop-cache`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

---

### Task 1: `SQLiteReplayStore` + schema + wiring

**Files:** `src/vinctor_service/sqlite.py` (table in `init_sqlite_schema`,
`schema_migrations` row, `SQLiteReplayStore` class near `SQLiteSubjectTokenRepository`,
the `__post_init__` swap), `src/vinctor_service/pop.py` (read its `PopReplayCache`
to mirror the contract + default `max_entries`); tests `tests/test_pop.py` (or a new
`tests/test_durable_pop_cache.py`) + the schema-version assertions in
`tests/test_cli.py` / `tests/test_storage_ops.py` / `tests/test_agent_enforcement_settings_repository.py`
/ `tests/test_subject_token_repository.py`.

- [x] **Step 1 — VERIFY current max schema version** via grep (`schema_migrations`
  INSERT rows + the test asserts). After arc I it is **8**; this arc adds **9**. Use
  `max+1` and adjust every assertion to match the actual current value.
- [x] **Step 2 — read `pop.py`** to copy the EXACT `check_and_record` signature, the
  default `max_entries`/`maxsize`, and the prune/replay/full semantics so the SQLite
  store is contract-identical.
- [x] **Step 3 — failing tests** (mirror `test_pop.py`'s replay + cache-full tests,
  but on a SQLite store):
  - first call records → True; identical `(token_id, nonce)` → False (replay).
  - **restart durability:** record on one `sqlite3.Connection`, then open a NEW
    connection on the SAME db file and assert the same `(token_id, nonce)` still
    denies (False).
  - **fail-closed when full:** with `max_entries=1`, one fresh entry held, a SECOND
    distinct fresh nonce → False (and the held entry is not evicted).
  - prune: an entry with `ts < now_unix - skew` no longer blocks a re-record.
  - the schema-version list now includes the new max.
- [x] **Step 4 — run, expect FAIL.**
- [x] **Step 5 — schema:** add the `pop_replay_nonces` CREATE TABLE to
  `init_sqlite_schema`; add the `INSERT OR IGNORE INTO schema_migrations VALUES
  (<new>, ...)` row after the prior block. (Optional index on `ts`.)
- [x] **Step 6 — store class:** add `SQLiteReplayStore` implementing
  `check_and_record(*, token_id, nonce, ts, now_unix, skew) -> bool` with a
  `threading.Lock`, the prune → replay-check → full-check → atomic-insert
  (IntegrityError → False) sequence above, storing the proof `ts`.
- [x] **Step 7 — wire:** in `SQLiteV1Service.__post_init__`, swap
  `self._pop_replay = PopReplayCache()` → `SQLiteReplayStore(self.conn)`. Leave
  `in_memory.py` on `PopReplayCache()`.
- [x] **Step 8 — bump EVERY schema-version assertion** to the new max (grep both the
  comma list and `== <prev>`); leave empty-DB cases.
- [x] **Step 9 — run tests + full suite + ruff; commit** `feat(pop): durable SQLite-backed PoP replay store`.

---

## Final
- [x] Full suite + `ruff check src/ tests/` green.
- [x] Update `docs/next-actions.md` (durable PoP replay cache shipped; note it is
  restart-durable + cross-process-correct via the PK; multi-process throughput
  tuning (WAL/busy_timeout) remains an optional further follow-up). Fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- The live SQLite service shares ONE `sqlite3.Connection` across `ThreadingHTTPServer`
  threads (`check_same_thread=False`); the `threading.Lock` serializes the
  multi-statement transaction within-process. The PK + IntegrityError handles
  cross-process/cross-thread races.
- Do NOT touch `in_memory.py`'s `PopReplayCache()` — `test_pop.py` exercises the
  in-memory path and must stay green.
- Scope note (intentionally NOT in this arc): forcing `PRAGMA journal_mode=WAL` +
  `busy_timeout` globally on the connection — that is a broader DB-file behavior
  change; the PK-enforced atomic dedup is already cross-process-correct without it.
