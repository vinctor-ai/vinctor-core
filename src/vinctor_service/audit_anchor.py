"""Audit chain-head anchoring (design §Anchor emission).

Emits each committed audit head {seq, row_hash, created_at} to a configured sink.
FAIL-OPEN by contract: a sink error is swallowed (logged to stderr) and NEVER
propagates into the enforce/audit-write path. Off by default (NullAnchor). The
first slice ships file + stdout sinks; network sinks (needing true async) land
later behind this same `emit` interface.
"""

from __future__ import annotations

import json
import sys
from typing import Protocol


class AuditAnchor(Protocol):
    def emit(self, seq: int, row_hash: str, created_at: str) -> None: ...


def _line(seq: int, row_hash: str, created_at: str) -> str:
    return json.dumps(
        {"seq": seq, "row_hash": row_hash, "created_at": created_at}, sort_keys=True
    )


class NullAnchor:
    """Anchoring disabled: no external writes, byte-compatible with pre-chain behavior."""

    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        return None


class StdoutAnchor:
    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        try:
            sys.stdout.write(_line(seq, row_hash, created_at) + "\n")
            sys.stdout.flush()
        except Exception as exc:  # fail-open
            sys.stderr.write(f"vinctor: audit anchor emit failed (stdout): {exc}\n")


class FileAnchor:
    def __init__(self, path: str) -> None:
        self._path = path

    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(_line(seq, row_hash, created_at) + "\n")
        except Exception as exc:  # fail-open: a dead anchor must never break enforce
            sys.stderr.write(f"vinctor: audit anchor emit failed (file): {exc}\n")


def anchor_from_env(env: dict[str, str]) -> AuditAnchor:
    """VINCTOR_AUDIT_ANCHOR: '' / unset -> off; 'stdout'; 'file:/abs/path'."""
    spec = (env.get("VINCTOR_AUDIT_ANCHOR") or "").strip()
    if not spec:
        return NullAnchor()
    if spec == "stdout":
        return StdoutAnchor()
    if spec.startswith("file:"):
        return FileAnchor(spec[len("file:"):])
    sys.stderr.write(
        f"vinctor: unknown VINCTOR_AUDIT_ANCHOR '{spec}'; anchoring disabled\n"
    )
    return NullAnchor()
