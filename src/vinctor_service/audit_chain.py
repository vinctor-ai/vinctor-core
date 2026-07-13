"""Tamper-evidence hash chain over the audit log (design:
docs/superpowers/specs/2026-07-12-audit-hash-chain-tamper-evidence-design.md).

Pure primitive + result types — no I/O. row_hash binds a row's sequence number,
its canonical event_json (json.dumps(..., sort_keys=True) — no literal newline,
so "\n" is a safe separator), and the previous row's hash.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

GENESIS_PREV_HASH = "0" * 64


def row_hash(seq: int, event_json: str, prev_hash: str) -> str:
    payload = f"{seq}\n{event_json}\n{prev_hash}".encode()
    return hashlib.sha256(payload).hexdigest()


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
