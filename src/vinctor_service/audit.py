from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from vinctor_core.audit import (
    EVENT_AUTH_FAILED,
    REASON_AUTH_FAILED,
    build_rejection_audit_event,
)
from vinctor_core.models import AuditEvent

# Aggregation window for audit-recorded authentication failures for the same
# (surface, source). See ADR 0008 item 2.
AUTH_FAILURE_WINDOW_SECONDS = 60


class AuditWriter(Protocol):
    def write(self, event: AuditEvent) -> None: ...


class InMemoryAuditWriter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


def record_rejection(audit_writer: AuditWriter, event: AuditEvent) -> None:
    """Write an operator-only rejection audit event, best-effort (ADR 0008).

    Auditing a pre-grant-evaluation rejection must never alter the caller-facing
    response: the caller already gets a generic, fail-closed rejection. If the
    audit store is unavailable we swallow the error rather than surfacing a 503
    (which would both change the response and leak that an event was attempted).
    """
    with contextlib.suppress(Exception):
        audit_writer.write(event)


@dataclass
class _AuthFailureWindow:
    """In-memory aggregation state for one (surface, source) window."""

    start: datetime
    last_seen: datetime
    count: int


class AuthFailureAuditThrottle:
    """Aggregate `auth_failed` audit events per window (ADR 0008 item 2).

    An attacker probing with bad credentials could otherwise turn failed-auth
    logging into an audit-store flood (a log-amplification DoS). Per
    (surface, source) window of ``window_seconds`` this emits:

    - one *timely* event immediately on the first failure of a window
      (``occurrence_count=1``, ``first_seen_at == last_seen_at == now``), so the
      operator gets a prompt signal that probing has started; and
    - one *summary* event when the next failure arrives after the window has
      elapsed, but only if the just-closed window saw more than one failure
      (``occurrence_count`` = total, with the window's first/last-seen span).

    Repeat failures within a window are counted in memory and do not emit. State
    is in-memory and per-process: it resets on restart, which at worst drops a
    pending summary and allows a small burst right after a restart.
    """

    def __init__(self, window_seconds: int = AUTH_FAILURE_WINDOW_SECONDS) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._windows: dict[tuple[str, str], _AuthFailureWindow] = {}

    def record(
        self,
        audit_writer: AuditWriter,
        *,
        surface: str,
        boundary_id: str | None,
        now: datetime,
    ) -> None:
        key = (surface, boundary_id or "-")
        window = self._windows.get(key)

        if window is not None and now - window.start < self._window:
            # Same window: count the repeat in memory, refresh last-seen, emit
            # nothing (the timely event for this window already fired).
            window.count += 1
            window.last_seen = now
            return

        # Window roll (or first failure ever for this key). If the just-closed
        # window aggregated more than its initial timely event, emit a summary
        # before opening the new window.
        if window is not None and window.count > 1:
            self._emit(
                audit_writer,
                surface=surface,
                boundary_id=boundary_id,
                created_at=window.last_seen,
                occurrence_count=window.count,
                first_seen_at=window.start,
                last_seen_at=window.last_seen,
            )

        # Open the new window and emit its timely first event.
        self._windows[key] = _AuthFailureWindow(start=now, last_seen=now, count=1)
        self._emit(
            audit_writer,
            surface=surface,
            boundary_id=boundary_id,
            created_at=now,
            occurrence_count=1,
            first_seen_at=now,
            last_seen_at=now,
        )

    def _emit(
        self,
        audit_writer: AuditWriter,
        *,
        surface: str,
        boundary_id: str | None,
        created_at: datetime,
        occurrence_count: int,
        first_seen_at: datetime,
        last_seen_at: datetime,
    ) -> None:
        # The credential is invalid, so no agent/workspace is resolvable; attribute
        # to the surface and (when present) the boundary only, and disclose nothing.
        record_rejection(
            audit_writer,
            build_rejection_audit_event(
                reason_code=REASON_AUTH_FAILED,
                workspace_id="",
                agent_id="",
                created_at=created_at,
                event_type=EVENT_AUTH_FAILED,
                action=surface,
                scope_attempted="",
                boundary_id=boundary_id,
                occurrence_count=occurrence_count,
                first_seen_at=first_seen_at,
                last_seen_at=last_seen_at,
            ),
        )
