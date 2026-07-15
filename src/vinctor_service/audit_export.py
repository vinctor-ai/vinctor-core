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
import time
from collections.abc import Callable
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
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


def _otlp_record(event: AuditEvent) -> dict[str, object]:
    attributes = {
        "vinctor.event_id": event.event_id,
        "vinctor.event_type": event.event_type,
        "vinctor.decision": event.decision,
        "vinctor.workspace_id": event.workspace_id,
        "vinctor.agent_id": event.agent_id,
        "vinctor.runtime": event.runtime or "",
    }
    return {
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


def _otlp_json(events: list[AuditEvent]) -> bytes:
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
                        "logRecords": [_otlp_record(event) for event in events],
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
        batch_size: int = 32,
        batch_wait: float = 0.05,
        max_attempts: int = 3,
        retry_backoff: float = 0.1,
        sleeper: Callable[[float], None] = time.sleep,
        sender: _OtlpSender = _send_otlp_http,
    ) -> None:
        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("OTLP HTTP endpoint must be an http(s) URL")
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if batch_wait < 0:
            raise ValueError("batch_wait must not be negative")
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if retry_backoff < 0:
            raise ValueError("retry_backoff must not be negative")
        self._endpoint = endpoint
        self._timeout = timeout
        self._batch_size = batch_size
        self._batch_wait = batch_wait
        self._max_attempts = max_attempts
        self._retry_backoff = retry_backoff
        self._sleeper = sleeper
        self._sender = sender
        self._queue: queue.Queue[AuditEvent | object] = queue.Queue(maxsize=queue_size)
        self._closed = False
        self._state_lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run,
            name="vinctor-otlp-export",
            daemon=True,
        )
        self._thread.start()

    def emit(self, event: AuditEvent) -> None:
        with self._state_lock:
            if self._closed:
                sys.stderr.write(
                    "vinctor: audit export is closed (otlp-http); event dropped\n"
                )
                return
            try:
                self._queue.put_nowait(event)
            except queue.Full:
                sys.stderr.write(
                    "vinctor: audit export queue full (otlp-http); event dropped\n"
                )

    def close(self, timeout: float = 2.0) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._queue.put(_STOP, timeout=timeout)
        except queue.Full:
            sys.stderr.write("vinctor: audit export close timed out (otlp-http)\n")
            return
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            sys.stderr.write("vinctor: audit export flush timed out (otlp-http)\n")

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is _STOP:
                self._queue.task_done()
                return
            assert isinstance(item, AuditEvent)
            batch = [item]
            stop_after_batch = False
            deadline = time.monotonic() + self._batch_wait
            while len(batch) < self._batch_size:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    next_item = self._queue.get(timeout=remaining)
                except queue.Empty:
                    break
                if next_item is _STOP:
                    self._queue.task_done()
                    stop_after_batch = True
                    break
                assert isinstance(next_item, AuditEvent)
                batch.append(next_item)
            try:
                self._send_batch(batch)
            finally:
                for _event in batch:
                    self._queue.task_done()
            if stop_after_batch:
                return

    def _send_batch(self, batch: list[AuditEvent]) -> None:
        data = _otlp_json(batch)
        for attempt in range(1, self._max_attempts + 1):
            try:
                self._sender(self._endpoint, data, self._timeout)
                return
            except Exception as exc:  # fail-open, outside the caller thread
                if attempt >= self._max_attempts or not _is_transient(exc):
                    sys.stderr.write(
                        f"vinctor: audit export emit failed (otlp-http): {exc}\n"
                    )
                    return
                try:
                    self._sleeper(self._retry_backoff * (2 ** (attempt - 1)))
                except Exception as sleep_error:
                    sys.stderr.write(
                        "vinctor: audit export retry wait failed "
                        f"(otlp-http): {sleep_error}\n"
                    )
                    return


def _is_transient(error: Exception) -> bool:
    if isinstance(error, HTTPError):
        return error.code in {408, 429} or 500 <= error.code < 600
    return isinstance(error, (URLError, TimeoutError, ConnectionError, OSError))


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
        # Stream the copy only after the durable write is committed. Backend
        # writers expose emit_or_defer so an export that joined an outer
        # transaction is held until the outermost commit and dropped on
        # rollback; writers without it (e.g. in-memory) emit inline.
        emit_or_defer = getattr(self._wrapped, "emit_or_defer", None)
        if emit_or_defer is not None:
            emit_or_defer(lambda: self._emit(event))
        else:
            self._emit(event)

    def _emit(self, event: AuditEvent) -> None:
        try:
            self._export.emit(event)
        except Exception as exc:  # fail-open, belt-and-braces over the sink contract
            sys.stderr.write(f"vinctor: audit export emit failed: {exc}\n")

    def close_export(self) -> None:
        close = getattr(self._export, "close", None)
        if callable(close):
            try:
                close()
            except Exception as exc:
                sys.stderr.write(f"vinctor: audit export close failed: {exc}\n")

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
            return OtlpHttpExport(
                endpoint,
                batch_size=_env_int(env, "VINCTOR_AUDIT_EXPORT_BATCH_SIZE", 32),
                max_attempts=_env_int(
                    env, "VINCTOR_AUDIT_EXPORT_MAX_ATTEMPTS", 3
                ),
                retry_backoff=_env_float(
                    env, "VINCTOR_AUDIT_EXPORT_RETRY_BACKOFF_SECONDS", 0.1
                ),
            )
        except ValueError as exc:
            sys.stderr.write(f"vinctor: invalid VINCTOR_AUDIT_EXPORT: {exc}; disabled\n")
            return NullExport()
    sys.stderr.write(
        f"vinctor: unknown VINCTOR_AUDIT_EXPORT '{spec}'; audit export disabled\n"
    )
    return NullExport()


def _env_int(env: dict[str, str], name: str, default: int) -> int:
    try:
        return int(env.get(name, str(default)))
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error


def _env_float(env: dict[str, str], name: str, default: float) -> float:
    try:
        return float(env.get(name, str(default)))
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error
