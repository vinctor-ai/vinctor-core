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

    def emit_storage_op(
        self, op: str, at: str, head_seq: int | None, head_hash: str | None
    ) -> None: ...


def _line(seq: int, row_hash: str, created_at: str) -> str:
    return json.dumps(
        {"seq": seq, "row_hash": row_hash, "created_at": created_at}, sort_keys=True
    )


def storage_op_line(op: str, at: str, head_seq: int | None, head_hash: str | None) -> str:
    """One-line JSON record for an operator storage op (backup/reset/restore/migrate).

    Self-identifying via "kind" so it can share a sink with chain-head records,
    which keep their exact pre-existing shape (no "kind" key). head_seq/head_hash
    are the PRE-op chain head; None/None means the head could not be read.
    """
    return json.dumps(
        {"kind": "storage_op", "op": op, "at": at, "head_seq": head_seq, "head_hash": head_hash},
        sort_keys=True,
    )


class NullAnchor:
    """Anchoring disabled: no external writes, byte-compatible with pre-chain behavior."""

    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        return None

    def emit_storage_op(
        self, op: str, at: str, head_seq: int | None, head_hash: str | None
    ) -> None:
        return None


class StdoutAnchor:
    def emit(self, seq: int, row_hash: str, created_at: str) -> None:
        try:
            sys.stdout.write(_line(seq, row_hash, created_at) + "\n")
            sys.stdout.flush()
        except Exception as exc:  # fail-open
            sys.stderr.write(f"vinctor: audit anchor emit failed (stdout): {exc}\n")

    def emit_storage_op(
        self, op: str, at: str, head_seq: int | None, head_hash: str | None
    ) -> None:
        try:
            sys.stdout.write(storage_op_line(op, at, head_seq, head_hash) + "\n")
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

    def emit_storage_op(
        self, op: str, at: str, head_seq: int | None, head_hash: str | None
    ) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(storage_op_line(op, at, head_seq, head_hash) + "\n")
        except Exception as exc:  # fail-open: a dead anchor must never block a storage op
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
