# Storage-ops tamper-evidence trace (stderr + anchor) — Design note

**Status:** Implemented on `feat/storage-ops-audit`.
**Date:** 2026-07-13
**Gap:** The audit hash chain + anchor (2026-07-12 spec) protects *appended events*, but the
operator storage ops (`backup`/`reset`/`restore`/`migrate` in `storage_ops.py`) act on the
SQLite file directly and silently — a `reset` wipes the chain, a `restore` replaces it, and
nothing independent records that it happened. Whoever can run these commands can erase the
tamper-evidence itself.

**What ships:** every storage op emits, at op entry and therefore BEFORE its destructive step,
one JSON record — op name, ISO-8601 UTC timestamp, pre-op chain head — to BOTH stderr (always,
even under `NullAnchor`) and the configured anchor (`anchor_from_env`, or an injected
`AuditAnchor`). After a wipe, the anchor still holds "the chain had reached (seq=N, hash=H)
at time T, then a reset ran".

**Record shape (the design decision):** the anchor's `emit(seq, row_hash, created_at)` is
chain-row-shaped, so storage ops use a sibling protocol method
`emit_storage_op(op, at, head_seq, head_hash)` on `AuditAnchor` + all three sinks, writing
`{"kind": "storage_op", "op": ..., "at": ..., "head_seq": ..., "head_hash": ...}`. Chosen over
(a) overloading `emit` (loses the op name, pollutes chain semantics) and (b) a separate sink
config (operators should not have to configure anchoring twice). Chain-head lines stay
byte-identical and never carry a `"kind"` key; `audit verify --against-anchor` skips
`"kind"`-tagged lines (it previously crashed on any non-chain line).

**Head semantics:** read directly from the DB file (mirrors `read_schema_versions`; never
creates/migrates). Absent DB or empty chain → `(0, GENESIS_PREV_HASH)`, matching
`chain_head()` / `operator audit head`. Unreadable DB → `null/null` + a stderr note — never
silently claimed empty. Records mean "op ATTEMPTED": they fire before validation too.

**Fail-open:** a failing head read or anchor sink logs to stderr and never blocks the storage
op — same posture as the chain's post-commit emit in `SQLiteAuditWriter.write`.

**Founder should check:** (1) the trace's independence is only as strong as the anchor sink —
same-host file anchors remain detection-only, per the 2026-07-12 gradient; (2) `"kind" not in d`
as the chain-vs-other discriminator in the verify parser; (3) "trace attempts, not just
successes" semantics; (4) no disclosure — record is op name + timestamp + a hash, nothing else.
