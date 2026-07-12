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
