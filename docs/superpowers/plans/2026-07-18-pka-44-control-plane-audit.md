# PKA-44: Control-plane actions are audited (`event_class` on the decision chain)

Implements ADR 0019 decisions 2 and 3 for the existing CLI-driven control paths.
Design is settled by the ADR + the Linear issue; this plan only sequences the
work. TDD: each task lands its failing test first, then the minimal code.

## Shape

- `AuditEvent` gains `event_class: str = "decision"`. `to_dict()` emits the key
  only when it is not `"decision"` (same omit-when-default convention as
  `identity_proven`), so every existing decision row — old or new — reads
  uniformly as "absent = decision" and decision-event canonical JSON stays
  byte-identical.
- `audit_events` gains a materialized `event_class TEXT NOT NULL DEFAULT
  'decision'` column on BOTH backends. It joins `_CROSSCHECK_COLUMNS` (shared
  tuple, parity-tested) with a normalization rule in `crosscheck_values_match`:
  an absent JSON key equals a `'decision'` column. Flipping the column on a
  control row without touching the hashed JSON is a `column_mismatch`.
- Schema versions bump: SQLite 14 → 15, Postgres 5 → 6. Every version
  assertion updates (inventoried below).
- New `vinctor_core.audit.build_control_audit_event(...)` builds control
  events: `event_class="control"`, `decision="permit"`, empty grant fields,
  new event types `enforcement_setting_changed`, `scope_bounds_set`,
  `policy_applied`, `policy_rolled_back`, `key_rotated`.
- New `vinctor_service/control_audit.py`: `ControlPlaneAuditor` wraps the
  service's audit writer. `record(...)` writes one control event;
  `composite()` is a context manager that suppresses inner `record` calls
  (thread-local depth) and REQUIRES the caller to set exactly one operation
  event, written inside the caller's still-open transaction — completing a
  composite without recording raises, which rolls the whole operation back.
  This is how `policy apply` (which drives the audited bounds/settings repos
  internally) emits exactly ONE `policy_applied` event.
- Control repos take the auditor as a REQUIRED constructor arg:
  `SQLiteAgentEnforcementSettingsRepository(conn, control_auditor)`,
  `SQLiteAgentIssuableScopeBoundsRepository(conn, control_auditor)`, and the
  Postgres twins. Their mutation methods wrap {upsert + record} in ONE
  transaction (`_atomic_write` on SQLite, `conn.transaction()` on Postgres).
  Key rotation audits at the operation level: `key_ops.rotate_*` gain a
  required `control_auditor` kwarg and record inside
  `repository.transaction()`. Policy apply/rollback record inside
  `_sqlite_apply_transaction` / `postgres_policy_apply_transaction`.
- Both services expose `self.control_auditor` (built from the final —
  possibly export-wrapped — `audit_writer`); the SQLite pool-state contract
  gains the field.
- SQLite transaction scopes that will now contain audit writes but lack the
  post-commit deferral bracket get it: `_sqlite_apply_transaction` and
  `SQLiteLocalKeyRepository.transaction()` wrap with
  `conn.atomic_write_deferral()` so anchor/export emissions flush only after
  the real commit (mirrors `_atomic_write`).
- Read surfaces that enumerate fields manually add `event_class`:
  `audit_http._audit_event_body`, MCP `output_policy.AUDIT_EVENT_SAFE_FIELDS`,
  OTLP `_otlp_record` (`vinctor.event_class`). CLI `_audit_body` uses
  `asdict` and picks it up automatically.
- No agent-facing change: no new `reason_code`, no control data in enforce
  responses. Guarded by a regression test.

## Out of scope (per the issue)

Remote operator HTTP surface; anchoring/external sink for control events;
auto-approval-rule standalone mutations; bootstrap `ensure_*` key creation;
the pre-existing Postgres anchor-emitted-inside-outer-transaction behavior
(identical for decision events today).

## Tasks

1. **Model + canonical JSON.** Failing tests: `event_class` default,
   `to_dict` omission rule, `_audit_event_from_json` round-trip (both
   backends' readers default absent → `decision`). Implement in
   `vinctor_core/models.py`, `sqlite.py`, `postgres.py` readers.
2. **Schema v15/v6 + crosscheck.** Failing tests: fresh-schema column,
   `15 in get_sqlite_schema_versions`, legacy-DB migration backfills
   `'decision'` and `verify_chain` stays ok, control-column tamper →
   `column_mismatch`, `crosscheck_values_match("event_class", None,
   "decision")`. Update every version assertion: tests
   test_agent_enforcement_settings_repository:35,
   test_subject_token_repository:59, test_policy_versions:104,
   test_durable_pop_cache:114, test_audit_list_filtered:81,
   test_storage_ops (9 sites), test_cli (690/691/856/860/932/933/969/1049),
   test_audit_hash_chain_sqlite:408 (+ keep :50), postgres.py:456 → (1..6).
   Writers materialize the column; `_CROSSCHECK_COLUMNS` extended on both
   (parity + coverage tests enforce).
3. **Control event builder + `ControlPlaneAuditor`.** Failing tests:
   builder field contract; `record` writes through the writer; `composite`
   suppresses inner records, writes exactly one, raises when none recorded,
   writes nothing when the body raises.
4. **SQLite settings + bounds repos audited & atomic.** Failing tests: each
   `set_*` emits exactly one control event with the documented shape;
   audit-writer failure rolls the setting back; missing-auditor construction
   fails (TypeError). Wire `SQLiteV1Service` (+ pool contract) and update
   existing constructor call sites in tests.
5. **Postgres settings + bounds repos** — same contract, tests in
   `tests/test_postgres_storage.py` (DSN-gated, run in CI).
6. **Policy apply/rollback: exactly one event each, atomic, both backends.**
   Apply uses `composite()` around `_apply_policy_document`; rollback records
   directly inside its transaction. Failing tests: one `policy_applied` for a
   document that also sets bounds + require_boundary; one
   `policy_rolled_back`; audit failure unwinds the whole apply (no bounds, no
   version row); chain verifies.
7. **Key rotation: one `key_rotated` per rotation, atomic, both backends.**
   `rotate_*` require `control_auditor`; CLI passes `service.control_auditor`.
   Failing tests: per-rotation event shape (workspace/agent/auditor/
   service-operator/pep), audit failure rolls the rotation back (new key
   absent, old keys still active).
8. **End-to-end + ordering + no-disclosure.** Both backends: toggle all three
   mandates, set bounds, apply, rollback, rotate → exactly 7 control events,
   `verify_chain().ok`, control seqs precede a following decision event's
   seq; a denied enforce after control ops returns the identical response
   shape/reason as before any control op (no new agent-facing surface).
9. **Read surfaces** (audit_http body, MCP safe fields, OTLP attribute) +
   full suite + `ruff check` + demo sanity.
10. **Codex adversarial review**; fix findings; repeat until clean. Then PR.

## Verification

`.venv/bin/python -m pytest` green locally (SQLite paths; PG tests skip
without DSN), `.venv/bin/ruff check` clean, demos still pass (CI runs them),
Codex review clean. PR against main; no merge.
