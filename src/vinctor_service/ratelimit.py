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
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address, ip_network

IpAddress = IPv4Address | IPv6Address
IpNetwork = IPv4Network | IPv6Network

# Bound request-supplied parsing work. The HTTP layer catches the resulting
# ValueError and fails open, as it does for every other limiter error.
MAX_X_FORWARDED_FOR_LENGTH = 4096


def parse_trusted_proxy_cidrs(raw: str | None) -> tuple[IpNetwork, ...]:
    """Parse a comma-separated trusted-proxy CIDR list.

    An unset or whitespace-only value is the secure default: trust no proxy.
    Invalid entries raise so the configuration boundary can fall back to that
    same default without partially trusting a malformed list.
    """
    if raw is None or not raw.strip():
        return ()
    entries = [entry.strip() for entry in raw.split(",")]
    if any(not entry for entry in entries):
        raise ValueError("trusted proxy CIDRs must not contain empty entries")
    return tuple(ip_network(entry, strict=False) for entry in entries)


def resolve_rate_limit_source(
    *,
    peer: str,
    forwarded_for: str | None,
    trusted_proxies: tuple[IpNetwork, ...],
) -> str:
    """Resolve a rate-limit key without trusting caller-supplied forwarding data.

    With no configured trusted proxies, this returns the socket peer verbatim.
    Otherwise X-Forwarded-For is considered only when that immediate peer is
    trusted, then walked right-to-left to select the rightmost non-proxy hop.

    Malformed forwarding data falls back to the peer rather than raising. The
    caller's guard turns an exception into "allow", which would mean unparseable
    input *disables* the limiter — and this input is attacker-influenced, so
    that would hand anyone able to reach a misconfigured proxy an unlimited
    budget. Degrading to the peer's bucket keeps limiting on a key we know is
    real; the caller's guard stays for genuinely unexpected failures.
    """
    if not trusted_proxies:
        return peer

    peer_address = ip_address(peer)
    if not _is_trusted(peer_address, trusted_proxies):
        return peer
    if forwarded_for is None:
        return peer
    if len(forwarded_for) > MAX_X_FORWARDED_FOR_LENGTH:
        return peer

    for entry in reversed(forwarded_for.split(",")):
        try:
            candidate = ip_address(entry.strip())
        except ValueError:
            # Nothing left of an unparseable hop can be trusted either — the
            # chain is only meaningful read right-to-left from a known-good end.
            return peer
        if not _is_trusted(candidate, trusted_proxies):
            return str(candidate)

    # A chain containing only trusted proxies has no attributable client hop.
    # Keep those requests in the immediate peer's bucket.
    return peer


def _is_trusted(address: IpAddress, networks: tuple[IpNetwork, ...]) -> bool:
    return any(address in network for network in networks)


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
