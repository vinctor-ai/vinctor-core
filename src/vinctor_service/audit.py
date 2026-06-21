from __future__ import annotations

import contextlib
from datetime import datetime, timedelta
from typing import Protocol

from vinctor_core.audit import build_rejection_audit_event
from vinctor_core.models import AuditEvent

# Minimum gap between audit-recorded authentication failures for the same
# (surface, source). See ADR 0008 item 2.
AUTH_FAILURE_WINDOW_SECONDS = 60


class AuditWriter(Protocol):
    def write(self, event: AuditEvent) -> None: ...


class InMemoryAuditWriter:
    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def write(self, event: AuditEvent) -> None:
        self.events.append(event)


class AuthFailureAuditThrottle:
    """Rate-limit `auth_failed` audit events (ADR 0008 item 2).

    An attacker probing with bad credentials could otherwise turn failed-auth
    logging into an audit-store flood (a log-amplification DoS). This emits at
    most one `auth_failed` event per (surface, source) per window. State is
    in-memory and per-process: it resets on restart, which at worst allows a
    small burst of events right after a restart.
    """

    def __init__(self, window_seconds: int = AUTH_FAILURE_WINDOW_SECONDS) -> None:
        self._window = timedelta(seconds=window_seconds)
        self._last_emitted: dict[tuple[str, str], datetime] = {}

    def record(
        self,
        audit_writer: AuditWriter,
        *,
        surface: str,
        boundary_id: str | None,
        now: datetime,
    ) -> None:
        key = (surface, boundary_id or "-")
        last = self._last_emitted.get(key)
        if last is not None and now - last < self._window:
            return
        self._last_emitted[key] = now
        # The credential is invalid, so no agent/workspace is resolvable; attribute
        # to the surface and (when present) the boundary only, and disclose nothing.
        with contextlib.suppress(Exception):
            audit_writer.write(
                build_rejection_audit_event(
                    reason="auth_failed",
                    workspace_id="",
                    agent_id="",
                    created_at=now,
                    event_type="auth_failed",
                    action=surface,
                    scope_attempted="",
                    boundary_id=boundary_id,
                )
            )
