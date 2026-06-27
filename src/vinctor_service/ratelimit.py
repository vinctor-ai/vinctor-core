"""Opt-in, per-source, fixed-window request rate limiter (availability tool).

Stdlib only, in-memory, per-process. Mirrors the lock/prune idiom of
``PopReplayCache`` but FAILS OPEN: this is an availability guard, not an authz
gate, so a full source table never denies a brand-new source (a limiter that
fail-closes would itself be a DoS vector). The HTTP layer builds one shared
instance only when ``VINCTOR_RATE_LIMIT_PER_MINUTE`` is a positive int; with the
var unset there is no limiter and no behavior change.
"""

from __future__ import annotations

import threading


class FixedWindowRateLimiter:
    """Per-source fixed-window counter, thread-safe and memory-bounded.

    ``allow(source, now)`` returns True when the request may proceed. Within a
    ``window_seconds`` window each source is permitted up to ``max_requests``
    calls; the next call in the same window returns False. Mutation happens under
    a single ``threading.Lock`` so concurrent handler threads serialize the
    read-modify-write. The source table is capped at ``max_sources``: a brand-new
    source that would overflow the table is ALLOWED without being tracked
    (fail-open), and expired windows are pruned before that capacity check so a
    burst of new sources cannot permanently lock out tracking.
    """

    def __init__(
        self,
        *,
        max_requests: int,
        window_seconds: int = 60,
        max_sources: int = 10000,
    ) -> None:
        # The caller only builds the limiter when the configured value is
        # positive; a non-positive max_requests is a programming error.
        if max_requests <= 0:
            raise ValueError("max_requests must be positive")
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._max_sources = max_sources
        # source -> (window_start, count)
        self._windows: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str, now: float) -> bool:
        with self._lock:
            # Prune expired windows first so capacity reflects only live sources.
            if self._windows:
                for key in [
                    k
                    for k, (start, _) in self._windows.items()
                    if now - start >= self._window_seconds
                ]:
                    del self._windows[key]

            entry = self._windows.get(source)
            if entry is None:
                if len(self._windows) >= self._max_sources:
                    # Table full of live sources: fail OPEN, do not insert.
                    return True
                self._windows[source] = (now, 1)
                return True

            # Pruning above already removed any expired window, so a present
            # entry is always live (now - start < window_seconds).
            start, count = entry
            if count < self._max_requests:
                self._windows[source] = (start, count + 1)
                return True
            # At the limit: deny without incrementing further.
            return False
