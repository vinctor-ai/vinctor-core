"""Audit event export for SIEM/OTel pipelines (opt-in).

Streams each persisted audit event to a configured sink — the same data already
written to the durable audit store, ALSO copied out for external collection.
FAIL-OPEN by contract: a sink error is swallowed (logged to stderr) and NEVER
propagates into the enforce/audit-write path. Off by default (NullExport).
"""

from __future__ import annotations

import json
import queue
import sys
import threading
from collections.abc import Callable
from typing import Any, Protocol
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

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


_STOP = object()
_OtlpSender = Callable[[str, bytes, float], None]


def _send_otlp_http(endpoint: str, data: bytes, timeout: float) -> None:
    request = Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - configured endpoint
        response.read()


def _otlp_json(event: AuditEvent) -> bytes:
    attributes = {
        "vinctor.event_id": event.event_id,
        "vinctor.event_type": event.event_type,
        "vinctor.decision": event.decision,
        "vinctor.workspace_id": event.workspace_id,
        "vinctor.agent_id": event.agent_id,
        "vinctor.runtime": event.runtime or "",
    }
    payload = {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "vinctor"}}
                    ]
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "vinctor.audit"},
                        "logRecords": [
                            {
                                "timeUnixNano": str(
                                    int(event.created_at.timestamp()) * 1_000_000_000
                                    + event.created_at.microsecond * 1_000
                                ),
                                "body": {"stringValue": _line(event)},
                                "attributes": [
                                    {"key": key, "value": {"stringValue": value}}
                                    for key, value in attributes.items()
                                ],
                            }
                        ],
                    }
                ],
            }
        ]
    }
    return json.dumps(payload, sort_keys=True).encode("utf-8")


class OtlpHttpExport:
    """Best-effort OTLP/HTTP JSON export outside the audit-write call path."""

    def __init__(
        self,
        endpoint: str,
        *,
        timeout: float = 1.0,
        queue_size: int = 1024,
        sender: _OtlpSender = _send_otlp_http,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("OTLP HTTP endpoint must be an http(s) URL")
        self._endpoint = endpoint
        self._timeout = timeout
        self._sender = sender
        self._queue: queue.Queue[bytes | object] = queue.Queue(maxsize=queue_size)
        self._thread = threading.Thread(
            target=self._run,
            name="vinctor-otlp-export",
            daemon=True,
        )
        self._thread.start()

    def emit(self, event: AuditEvent) -> None:
        try:
            self._queue.put_nowait(_otlp_json(event))
        except queue.Full:
            sys.stderr.write("vinctor: audit export queue full (otlp-http); event dropped\n")

    def close(self, timeout: float = 2.0) -> None:
        self._queue.put(_STOP, timeout=timeout)
        self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                assert isinstance(item, bytes)
                try:
                    self._sender(self._endpoint, item, self._timeout)
                except Exception as exc:  # fail-open, outside the caller thread
                    sys.stderr.write(
                        f"vinctor: audit export emit failed (otlp-http): {exc}\n"
                    )
            finally:
                self._queue.task_done()


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
    """Select the opt-in audit export sink from ``VINCTOR_AUDIT_EXPORT``."""
    spec = (env.get("VINCTOR_AUDIT_EXPORT") or "").strip()
    if not spec:
        return NullExport()
    if spec == "stdout":
        return StdoutExport()
    if spec.startswith("file:"):
        return FileExport(spec[len("file:"):])
    if spec.startswith("otlp-http:"):
        endpoint = spec[len("otlp-http:"):]
        try:
            return OtlpHttpExport(endpoint)
        except ValueError as exc:
            sys.stderr.write(f"vinctor: invalid VINCTOR_AUDIT_EXPORT: {exc}; disabled\n")
            return NullExport()
    sys.stderr.write(
        f"vinctor: unknown VINCTOR_AUDIT_EXPORT '{spec}'; audit export disabled\n"
    )
    return NullExport()
