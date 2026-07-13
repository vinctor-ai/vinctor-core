"""Audit event export for SIEM/OTel pipelines (opt-in).

Streams each persisted audit event to a configured sink as one JSON line
(``AuditEvent.to_dict()``, sorted keys) — the same data already written to the
durable audit store, ALSO copied out for external collection. FAIL-OPEN by
contract: a sink error is swallowed (logged to stderr) and NEVER propagates
into the enforce/audit-write path. Off by default (NullExport). The first
slice ships file + stdout sinks (JSON-lines a collector can tail); network
sinks (OTLP etc.) land later behind this same `emit` interface.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Protocol

from vinctor_core.models import AuditEvent
from vinctor_service.audit import AuditWriter


class AuditExport(Protocol):
    def emit(self, event: AuditEvent) -> None: ...


def _line(event: AuditEvent) -> str:
    return json.dumps(event.to_dict(), sort_keys=True)


class NullExport:
    """Export disabled: no external writes, byte-compatible with prior behavior."""

    def emit(self, event: AuditEvent) -> None:
        return None


class StdoutExport:
    def emit(self, event: AuditEvent) -> None:
        try:
            sys.stdout.write(_line(event) + "\n")
            sys.stdout.flush()
        except Exception as exc:  # fail-open
            sys.stderr.write(f"vinctor: audit export emit failed (stdout): {exc}\n")


class FileExport:
    def __init__(self, path: str) -> None:
        self._path = path

    def emit(self, event: AuditEvent) -> None:
        try:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(_line(event) + "\n")
        except Exception as exc:  # fail-open: a dead export must never break enforce
            sys.stderr.write(f"vinctor: audit export emit failed (file): {exc}\n")


class ExportingAuditWriter:
    """Decorator: persist via the wrapped writer FIRST, then stream a copy.

    The durable write always completes before the export is attempted, and an
    export failure — even a sink violating its own no-raise contract — is
    swallowed to stderr, so exporting never affects whether/what gets persisted.
    """

    def __init__(self, wrapped: AuditWriter, export: AuditExport) -> None:
        self._wrapped = wrapped
        self._export = export

    def write(self, event: AuditEvent) -> None:
        self._wrapped.write(event)
        try:
            self._export.emit(event)
        except Exception as exc:  # fail-open, belt-and-braces over the sink contract
            sys.stderr.write(f"vinctor: audit export emit failed: {exc}\n")

    def __getattr__(self, name: str) -> Any:
        # The service reads audit history through the same writer object
        # (list_all / get / list_filtered / chain_head); delegate everything
        # except `write` to the wrapped writer unchanged.
        return getattr(self._wrapped, name)


def audit_export_from_env(env: dict[str, str]) -> AuditExport:
    """VINCTOR_AUDIT_EXPORT: '' / unset -> off; 'stdout'; 'file:/abs/path'."""
    spec = (env.get("VINCTOR_AUDIT_EXPORT") or "").strip()
    if not spec:
        return NullExport()
    if spec == "stdout":
        return StdoutExport()
    if spec.startswith("file:"):
        return FileExport(spec[len("file:"):])
    sys.stderr.write(
        f"vinctor: unknown VINCTOR_AUDIT_EXPORT '{spec}'; audit export disabled\n"
    )
    return NullExport()
