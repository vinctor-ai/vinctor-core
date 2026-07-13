from __future__ import annotations

import threading

from vinctor_service.ratelimit import FixedWindowRateLimiter


def test_allows_up_to_max_then_denies_within_window() -> None:
    limiter = FixedWindowRateLimiter(max_requests=3, window_seconds=60)

    assert limiter.allow("1.2.3.4", now=1000.0) is True
    assert limiter.allow("1.2.3.4", now=1000.0) is True
    assert limiter.allow("1.2.3.4", now=1000.0) is True
    # The 4th request in the same window is denied.
    assert limiter.allow("1.2.3.4", now=1000.0) is False
    # A denied request does not keep incrementing into the next window oddly:
    # still denied while the window holds.
    assert limiter.allow("1.2.3.4", now=1059.9) is False


def test_window_reset_allows_again() -> None:
    limiter = FixedWindowRateLimiter(max_requests=2, window_seconds=60)

    assert limiter.allow("1.2.3.4", now=1000.0) is True
    assert limiter.allow("1.2.3.4", now=1000.0) is True
    assert limiter.allow("1.2.3.4", now=1000.0) is False
    # After the window elapses, the source is allowed again.
    assert limiter.allow("1.2.3.4", now=1060.0) is True
    assert limiter.allow("1.2.3.4", now=1060.0) is True
    assert limiter.allow("1.2.3.4", now=1060.0) is False


def test_per_source_isolation() -> None:
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60)

    assert limiter.allow("A", now=1000.0) is True
    assert limiter.allow("A", now=1000.0) is False
    # Source B is unaffected by source A being at its limit.
    assert limiter.allow("B", now=1000.0) is True
    assert limiter.allow("B", now=1000.0) is False


def test_memory_bound_fail_open_for_new_source_when_full() -> None:
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60, max_sources=2)

    # Fill the table with two distinct sources within the window.
    assert limiter.allow("A", now=1000.0) is True
    assert limiter.allow("B", now=1000.0) is True
    # A brand-new source cannot be inserted (table full) -> fail OPEN (allowed),
    # and it must NOT be tracked (no slot consumed).
    assert limiter.allow("C", now=1000.0) is True
    assert limiter.allow("C", now=1000.0) is True
    # Existing tracked sources still enforce their own limit.
    assert limiter.allow("A", now=1000.0) is False
    assert limiter.allow("B", now=1000.0) is False


def test_expired_entries_pruned_before_capacity_check() -> None:
    limiter = FixedWindowRateLimiter(max_requests=1, window_seconds=60, max_sources=2)

    assert limiter.allow("A", now=1000.0) is True
    assert limiter.allow("B", now=1000.0) is True
    # A and B are now expired. A brand-new source after the window should prune
    # them first and then be admitted into the table (and enforced thereafter).
    assert limiter.allow("C", now=2000.0) is True
    assert limiter.allow("C", now=2000.0) is False


def test_has_a_threading_lock() -> None:
    limiter = FixedWindowRateLimiter(max_requests=5, window_seconds=60)
    assert isinstance(limiter._lock, type(threading.Lock()))


def test_concurrency_smoke_stays_within_limit_per_source() -> None:
    # N threads x M calls against one source within a single window must never
    # admit more than max_requests (the lock serializes the read-modify-write).
    max_requests = 50
    limiter = FixedWindowRateLimiter(max_requests=max_requests, window_seconds=60)

    allowed = 0
    allowed_lock = threading.Lock()

    def worker() -> None:
        nonlocal allowed
        for _ in range(20):
            if limiter.allow("same-source", now=1000.0):
                with allowed_lock:
                    allowed += 1

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert allowed == max_requests
