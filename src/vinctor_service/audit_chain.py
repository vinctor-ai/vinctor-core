"""Tamper-evidence hash chain over the audit log (design:
docs/superpowers/specs/2026-07-12-audit-hash-chain-tamper-evidence-design.md).

Pure primitive + result types — no I/O. row_hash binds a row's sequence number,
its canonical event_json (json.dumps(..., sort_keys=True) — no literal newline,
so "\n" is a safe separator), and the previous row's hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

GENESIS_PREV_HASH = "0" * 64


def row_hash(seq: int, event_json: str, prev_hash: str) -> str:
    payload = f"{seq}\n{event_json}\n{prev_hash}".encode()
    return hashlib.sha256(payload).hexdigest()


# Materialized-column cross-check (verify_chain, both backends): event_json is
# canonical, and every audit_events column that mirrors one of its fields must
# agree with it, or a DB-write attacker could skew what filters/readers see
# without breaking the hash chain. Comparison is type-normalized so driver
# differences (SQLite ISO TEXT / 0-1 vs Postgres TIMESTAMPTZ / BOOLEAN) never
# produce false breaks on a healthy chain.
_DATETIME_CROSSCHECK_FIELDS = frozenset({"created_at", "first_seen_at", "last_seen_at"})
_BOOLEAN_CROSSCHECK_FIELDS = frozenset({"identity_proven"})


def _canonical_instant(value: object) -> object:
    """Canonical UTC ISO-8601 string for datetimes / ISO strings; anything else
    (None, non-ISO text) passes through unchanged for a raw comparison."""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            value = value.astimezone(UTC)
        return value.isoformat()
    return value


def crosscheck_values_match(column: str, json_value: object, column_value: object) -> bool:
    """True when a materialized audit column agrees with its event_json field.

    - datetimes (created_at, first_seen_at, last_seen_at): compared as UTC
      instants, whether stored as ISO-8601 TEXT (SQLite) or returned as a
      tz-aware datetime in the session timezone (Postgres TIMESTAMPTZ).
    - booleans (identity_proven): compared as Python bools; AuditEvent.to_dict
      omits the JSON key when False, and backends store 0/1 or BOOLEAN.
    - event_class: AuditEvent.to_dict omits the key when "decision" (and
      pre-event_class rows never carried it), so an absent JSON field equals a
      'decision' column; any other divergence — e.g. a control row's column
      flipped to 'decision' to hide it from per-category readers — is a break.
    - everything else (nullable text, integers): direct equality, with SQL NULL
      equal to an absent-or-null JSON field (both arrive here as None).
    """
    if column in _DATETIME_CROSSCHECK_FIELDS:
        return _canonical_instant(json_value) == _canonical_instant(column_value)
    if column in _BOOLEAN_CROSSCHECK_FIELDS:
        return bool(json_value) == bool(column_value)
    if column == "event_class":
        return (json_value if json_value is not None else "decision") == column_value
    return json_value == column_value


@dataclass(frozen=True)
class ChainVerification:
    ok: bool
    count: int
    head_seq: int
    head_hash: str
    break_seq: int | None = None
    break_event_id: str | None = None
    break_kind: str | None = None  # modified | deleted | reordered | column_mismatch


@dataclass(frozen=True)
class AnchorRecord:
    seq: int
    row_hash: str


@dataclass(frozen=True)
class AnchorVerification:
    ok: bool
    checked: int
    covered_max_seq: int
    divergence_seq: int | None = None
    divergence_kind: str | None = None  # missing | mismatch
