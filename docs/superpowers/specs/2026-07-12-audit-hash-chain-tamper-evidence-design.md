# Audit hash-chain + anchoring (tamper detection & prevention) — Design

**Status:** Approved (brainstorming) — ready for writing-plans.
**Date:** 2026-07-12
**Context:** The 2026-07-12 adoption review (a 5-persona panel + Codex, independently) demonstrated that Vinctor's SQLite audit log is freely mutable: a row could be silently `DELETE`d and a `deny` event rewritten into a `permit` by editing `event_json`, with `operator audit list` serving the forged record and no integrity warning. There is no hash chain, signature, sequence commitment, or WORM. For an authorization control whose strongest differentiator is its audit trail, an editable book-of-record is the sharpest gap the review found.

**What this spec is:** the tamper model for the audit log — **how far we can DETECT** modification/deletion/reordering, and **how far we can PREVENT** *undetectable* tampering. Detection comes from a per-DB hash chain + a `verify` walk. Prevention comes from continuously anchoring the chain head to an independent sink — and its strength is an explicit gradient in the destination's independence, not a blanket claim.

## Goals

1. **Detect** any after-the-fact modification, deletion, or reordering of audit rows by anyone with access to the SQLite file.
2. **Prevent undetectable tampering** by emitting the chain head to an external anchor. Against a DB-controlling attacker, a plain local chain is only *evident* (they can recompute the whole tail — cheap, unkeyed SHA-256). Anchoring the head where the attacker cannot rewrite it converts "recompute the chain" into "find a SHA-256 collision that matches the anchored head" — computationally infeasible. So with an independent anchor the log becomes **effectively tamper-resistant**, bounded only by the anchor cadence.

## Threat model — the detection/prevention gradient (honest)

Detection (chain + `verify`) is unconditional. Prevention is a **property of where the head is anchored** — a same-host, same-privilege sink is theater (the attacker owns it too), so the guarantee scales with the sink's independence:

| Anchor destination | Guarantee against a DB-controlling attacker |
| --- | --- |
| **None** | Tamper-**evident** only: a surgical single-row edit breaks the chain and is caught, but a full-tail recompute is internally valid and undetectable without any independent reference. |
| Same-host, same-privilege file | Still only evident — the attacker rewrites the anchor too. **We do not count this as prevention.** |
| OS-separated local sink (append-only `chattr +a` / root-owned / WORM mount) | **Resistant** up to defeating that OS separation (same class as the mcp-pep config-integrity story). |
| Independent external sink (remote host/service, syslog, transparency log) | **Effectively resistant.** The only exposure is the un-anchored tail — events appended since the last anchor. Anything at or before an anchored head can't be silently altered without producing a head that disagrees with the record. |

**Residual, stated plainly:** (a) the window since the last anchor (anchor cadence = exposure size); (b) if the operator points the sink somewhere the attacker controls, the guarantee degrades to detection-only. Cryptographic signing (Ed25519/HMAC) is a *different* lever and remains a non-goal (see below).

This is additive: no enforce decision changes; the audit **write** gains chain metadata + an async anchor emit, the audit **read** path is unchanged.

## Architecture

Five units, each independently testable:

1. **Chain primitive** (pure) — row hash + genesis constant.
2. **Append integration** — `SQLiteAuditWriter.write` extends the row with chain metadata in its existing serialized transaction.
3. **Migration / back-fill** — schema migration adds columns and chains existing rows from genesis.
4. **Verify + head** — read-only `operator audit verify` / `head`, including `verify --against-anchor`.
5. **Anchor emission** — continuous, async, fail-open head emission to a configured sink.

### 1. Chain primitive (`src/vinctor_service/audit_chain.py`, new)

```python
GENESIS_PREV_HASH = "0" * 64  # 64 hex zeros

def row_hash(seq: int, event_json: str, prev_hash: str) -> str:
    """sha256 over seq, the canonical event_json, and the prior row's hash.

    event_json is the already-canonical (json.dumps(..., sort_keys=True)) string
    stored in the row — it contains no literal newline (json escapes them), so
    "\n" is a safe field separator.
    """
    payload = f"{seq}\n{event_json}\n{prev_hash}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
```

- `seq`: 1-based, gapless, strictly monotonic. A missing `seq` is a deleted row; a non-monotonic `seq` is a reorder.
- Genesis: the first row uses `prev_hash = GENESIS_PREV_HASH`.
- The hash binds `event_json`, the authoritative content the read path reconstructs from (`_audit_event_from_json`). Denormalized columns are cross-checked in verify (below).

### 2. Append integration (`SQLiteAuditWriter.write`, `sqlite.py:1053`)

Within the existing `with self._conn:` transaction (already serialized process-wide by `db_access_lock`, so no interleaving between the head read and the insert):

1. `SELECT seq, row_hash FROM audit_events ORDER BY seq DESC LIMIT 1` → `(prev_seq, prev_hash)`, or `(0, GENESIS_PREV_HASH)` if empty.
2. `seq = prev_seq + 1`; `rh = row_hash(seq, event_json, prev_hash)` with the exact `json.dumps(event_data, sort_keys=True)` already stored.
3. Insert including the three new columns.
4. After the transaction commits, hand `(seq, rh, created_at)` to the anchor emitter (unit 5) — **outside** the DB lock, async, non-blocking.

`record_auth_failure` and any other audit-writing path go through the same insert, so all rows are chained.

### 3. Migration / back-fill

Idempotent `_ensure_audit_events_hashchain_columns(conn)` (mirrors `_ensure_agent_enforcement_require_pop_column`):

- `ALTER TABLE audit_events ADD COLUMN seq INTEGER / prev_hash TEXT / row_hash TEXT` if absent (guarded by `PRAGMA table_info`).
- Back-fill existing rows in **`rowid` ascending** order (the current insertion order the read path already assumes): assign `seq = 1..N`, compute the chain from genesis, `UPDATE` each row. Deterministic because `event_json` is canonical.
- Register the next `schema_migrations` version with `INSERT OR IGNORE`.

After migration the whole history verifies from genesis.

### 4. Verify + head

**Read helpers on `SQLiteAuditWriter` (or a dedicated reader):**

- `verify_chain() -> ChainVerification` — walk rows in `seq` order from 1:
  - recompute `row_hash` and compare to stored → `modified` on mismatch;
  - check `prev_hash` == prior row's stored `row_hash` (genesis for seq 1) → `reordered`/broken-link;
  - check `seq` gapless + monotonic → `deleted` on a gap;
  - for each denormalized column that also appears in `event_json` (`workspace_id`, `agent_id`, `grant_ref`, `action`, `resource`, `boundary_id`, …), check the column equals that `event_json` field → `column_mismatch` (catches editing a filter column to hide a row from a filtered `audit list` while leaving `event_json`, and thus the row hash, intact).
  - Return `ok=True` with `{head_seq, head_hash, count}`, else `ok=False` with the first break `{seq, event_id, kind ∈ {modified, deleted, reordered, column_mismatch}}`.
- `verify_against_anchor(records) -> AnchorVerification` — given recorded heads `[(seq_a, hash_a), …]`, assert each anchored `hash_a` equals the live chain's `row_hash` at `seq_a` (and that `seq_a` still exists). Any mismatch/missing seq → the chain was rewritten or rolled back at/before an anchored point. Reports the covered window and the first divergence.
- `chain_head() -> {seq, row_hash}` — current tip (genesis sentinel if empty).

**CLI (`operator audit`, `cli.py:586`):**

- `operator audit verify [--db <path>] [--expected-head <hash>] [--against-anchor <path|->] [-o json]` — runs `verify_chain()`; non-zero exit on any break. `--expected-head` fails if the live head ≠ the supplied value even when internally valid (single-checkpoint truncation/rollback catch). `--against-anchor` reads a head-log (file or stdin) and runs `verify_against_anchor()` (continuous-anchor catch).
- `operator audit head [--db <path>] [-o json]` — prints `{seq, row_hash}` (manual anchor / spot check).

All read-only, whole-DB (integrity is not workspace-scoped), `-o json` first with text fallback.

### 5. Anchor emission (`src/vinctor_service/audit_anchor.py`, new)

A small, pluggable emitter that receives each committed head and writes it to the configured sink(s). Requirements:

- **Off by default** — no anchor configured ⇒ no external writes, byte-compatible with today, and no false sense of prevention.
- **Configured** via operator setting / env (e.g. `VINCTOR_AUDIT_ANCHOR=file:/secured/vinctor-anchor.log` | `stdout` | `syslog:…` | `https://…webhook`). Sink kinds land incrementally; the first slice ships **append-file** and **stdout** (the two that need no network), with the interface shaped for syslog/webhook next.
- **Async + fail-open** — emission happens off the enforce path; a slow, unreachable, or failing sink **never** blocks, delays, or denies an enforce, and never drops an audit row. A failed emit is itself recorded to stderr/self-audit as an anchoring gap (so a silently-dead anchor is visible), but is not fatal. The security consequence of a missed emit is a larger un-anchored window, never a broken decision path.
- **Batched/interval-capable** — emit every head, or coalesce to the latest head every N events / T seconds (config). Cadence is the exposure/exposition tradeoff; the emitter records enough that `verify --against-anchor` can check every anchored point.
- **Line format** — one JSON line per anchor `{seq, row_hash, created_at}`, append-only, so the sink is itself a trivially-verifiable head-log.

Docs describe the hardening ladder: point the file sink at an OS-separated location (`chattr +a`, root-owned, or a WORM/remote mount), or a remote syslog/webhook, to climb the gradient to effective resistance.

## Data flow

```
enforce/reject → AuditEvent → SQLiteAuditWriter.write
    → [serialized txn] read head → seq=head+1 → row_hash → INSERT(+seq,prev_hash,row_hash)
    → (post-commit, async, fail-open) anchor.emit({seq,row_hash,created_at}) → sink

operator audit verify → walk seq 1..N → recompute+link+gap+column checks → first break | OK(head)
              [--expected-head H]     → also fail if live head ≠ H
              [--against-anchor SRC]  → replay recorded heads vs live chain → first divergence | OK(window)
operator audit head → {seq,row_hash}
```

## Error handling

- **Empty log:** `head` → genesis sentinel `{seq:0, row_hash:GENESIS_PREV_HASH}`; `verify` → `ok=True, count=0`.
- **Legacy DB:** migration back-fills on first open (idempotent); an already-migrated DB is untouched.
- **Tampered `event_json`:** verify surfaces it as `modified` (hash mismatch) — verify never raises on a tampered DB, it reports.
- **`verify` never mutates** — no "repair" (repair would erase evidence).
- **Anchor sink unavailable/slow/failing:** fail-open — enforce and audit-write proceed; the emitter logs the anchoring gap. Restoring the sink resumes from the current head (a gap in the anchor-log is itself visible to `verify --against-anchor`).
- **Concurrency:** append is inside the existing serialized transaction; the anchor emit is post-commit and order-preserving; verify/head are read-only snapshots. No new locks.

## Testing (TDD)

Unit — chain primitive: genesis constant, `row_hash` determinism, separator safety.
Integration (SQLite), each red-before/green-after:
- append assigns gapless monotonic `seq` + a valid genesis-rooted chain;
- tamper: **modify** `event_json` → `verify` reports `modified`;
- tamper: **delete** a row → `deleted` (seq gap);
- tamper: **reorder/relink** → `reordered`;
- tamper: **edit a denormalized column** (event_json intact) → `column_mismatch`;
- **back-fill:** seed a pre-migration table (NULL chain cols) → migrate → `verify` OK from genesis;
- **`--expected-head`:** valid chain, head ≠ expected → non-zero;
- **empty log:** genesis sentinel + OK count 0;
- **concurrency:** many threads append (reuse the concurrency harness) → `verify` OK, gapless.
Anchor:
- emitter writes one JSON line per head to a file sink; content = live head;
- **`verify --against-anchor`:** a tail rewrite/rollback crossing an anchored head → divergence reported at that seq; a clean chain within the anchored window → OK with covered range;
- **fail-open:** a sink that raises/hangs does NOT block or fail `write`/enforce, and the row is still chained (assert the audit row exists + the gap is logged);
- **default off:** no anchor configured ⇒ no sink writes, behavior byte-identical.
CLI — `verify` / `head` output shape (`-o json`) + exit codes.
Regression — existing audit `list`/`export`/`get` tests stay green; `grep`-all schema-version assertions updated for the new migration version.

## Docs

- README "Audit Semantics": the tamper-evidence guarantee, `verify`/`head`, the anchor config, and — front and center — the **detection/prevention gradient table** (evident with no anchor → resistant with an independent anchor). No blanket "tamper-proof" claim.
- `docs/threat-model.md`: replace the determinism-only audit note with the gradient; state the un-anchored-window and sink-independence residuals.
- Cross-reference the adoption-review finding as addressed.

## Non-goals (this slice)

- **Cryptographic signing** (Ed25519/HMAC of the head). A different lever (non-repudiation), deferred to a future ADR; on a single node a local key is compromised alongside the DB (the PoP plaintext-secret problem), and anchoring already closes the DB-controlling-attacker residual. Revisit for a hosted/multi-node or TPM-backed tier.
- **Full-event streaming to a SIEM** (Option C). This slice streams the **head** (a tiny `{seq,row_hash}` anchor), not the event bodies. Whole-log export/streaming is a separate, larger effort.
- **Syslog/webhook sinks** beyond the interface — the first slice ships file + stdout sinks; network sinks land next behind the same emitter interface.
- **Auditing storage ops** (`storage reset/restore/backup` emitting their own events). `verify --against-anchor`/`--expected-head` already detect a restore/reset rollback via head divergence; explicit storage-op events are a small follow-up.
- No change to enforce semantics, the audit event schema's *meaning*, or the HTTP audit projection's fields.
