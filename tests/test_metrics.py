from __future__ import annotations

from vinctor_service.metrics import Metrics


def test_increment_and_render_prometheus_text() -> None:
    m = Metrics()
    m.increment(
        "vinctor_http_requests_total",
        method="POST",
        path="/v1/enforce",
        status="200",
    )
    m.increment(
        "vinctor_http_requests_total",
        method="POST",
        path="/v1/enforce",
        status="200",
    )
    m.increment("vinctor_enforce_decisions_total", decision="deny")
    out = m.render()
    assert "# TYPE vinctor_http_requests_total counter" in out
    assert (
        'vinctor_http_requests_total{method="POST",path="/v1/enforce",status="200"} 2'
        in out
    )
    assert 'vinctor_enforce_decisions_total{decision="deny"} 1' in out
    assert out.endswith("\n")


def test_observe_and_render_prometheus_histogram() -> None:
    m = Metrics()
    # Exact binary fractions so the rendered sum is deterministic.
    m.observe(
        "vinctor_http_request_duration_seconds",
        0.25,
        method="GET",
        path="/healthz",
    )
    m.observe(
        "vinctor_http_request_duration_seconds",
        0.5,
        method="GET",
        path="/healthz",
    )
    m.observe(
        "vinctor_http_request_duration_seconds",
        64.0,
        method="GET",
        path="/healthz",
    )
    out = m.render()
    assert "# TYPE vinctor_http_request_duration_seconds histogram" in out
    labels = 'method="GET",path="/healthz"'
    # Buckets are cumulative; le boundaries are inclusive.
    assert (
        f'vinctor_http_request_duration_seconds_bucket{{{labels},le="0.1"}} 0' in out
    )
    assert (
        f'vinctor_http_request_duration_seconds_bucket{{{labels},le="0.25"}} 1' in out
    )
    assert (
        f'vinctor_http_request_duration_seconds_bucket{{{labels},le="0.5"}} 2' in out
    )
    assert (
        f'vinctor_http_request_duration_seconds_bucket{{{labels},le="10"}} 2' in out
    )
    assert (
        f'vinctor_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} 3' in out
    )
    assert f"vinctor_http_request_duration_seconds_sum{{{labels}}} 64.75" in out
    assert f"vinctor_http_request_duration_seconds_count{{{labels}}} 3" in out
    assert out.endswith("\n")


def test_render_mixes_counters_and_histograms() -> None:
    m = Metrics()
    m.increment("vinctor_http_requests_total", method="GET", path="/healthz", status="200")
    m.observe("vinctor_http_request_duration_seconds", 0.25, method="GET", path="/healthz")
    out = m.render()
    assert "# TYPE vinctor_http_requests_total counter" in out
    assert "# TYPE vinctor_http_request_duration_seconds histogram" in out
    assert (
        'vinctor_http_requests_total{method="GET",path="/healthz",status="200"} 1'
        in out
    )
