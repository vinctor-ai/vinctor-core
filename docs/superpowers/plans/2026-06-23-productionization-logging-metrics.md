# Productionization D — structured access log + metrics (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Steps use `- [ ]`.

**Goal:** Add the two remaining productionization signals from `docs/next-actions.md`
("structured/exportable operational logging and metrics"): an **opt-in, leak-free
structured access log** and an **opt-in `/metrics` endpoint** (Prometheus text,
in-process counters). Both **default off**, preserving the current intentionally-
suppressed per-request logging posture. Stdlib only.

**Design (locked):**
- **Metrics enabled ⇔ a `Metrics` instance is passed** to the server; only then is
  the `/metrics` route active. Counters are in-process (per-process, like the audit
  throttle). Low-cardinality labels only — **no ids/keys/tokens/grant_refs**.
- **Access log opt-in via a bool** (`access_log`); when on, one JSON line per
  request to stderr with `{ts, method, path, status, latency_ms, decision?,
  error?}` — coarse fields only, **no ids/secrets/bodies**.
- **Integration:** `V1Handler` do_* methods route through a `_dispatch(method)`
  wrapper that records start time, runs `_handle_request`, and (in `finally`) calls
  `_observe`. `_send_json` records `handler._vinctor_status/_decision/_error` from
  the response. `_observe` increments counters (if metrics) and emits the log (if
  access_log). A new `/metrics` GET branch returns `metrics.render()` as
  `text/plain`.
- **Config:** `ServiceRuntimeConfig` gains `access_log: bool = False` +
  `metrics: bool = False`; `load_service_runtime_config` reads `VINCTOR_ACCESS_LOG`
  / `VINCTOR_METRICS` (truthy `"1"`/`"true"`); `service_runtime` constructs a
  `Metrics()` iff `config.metrics` and threads `access_log`; `vinctor service serve`
  gains `--access-log` / `--metrics` flags.

**Invariants:** default off → behavior byte-for-byte unchanged (no /metrics route,
no log lines, `log_message` still suppressed). Leak-free: nothing in metrics labels
or log lines may contain a key/token/grant_ref/raw id. Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/productionization-logging-metrics`, main human-merge-only. Commit trailer ends
with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`.

**Out of scope (named follow-ups):** Docker image publishing / tagged release
artifacts (needs registry/PyPI credentials — write the CI workflow only when creds
exist); per-metric `# HELP` text (optional).

---

### Task 1: `Metrics` + `/metrics` endpoint (opt-in) + request plumbing

**Files:** create `src/vinctor_service/metrics.py`; modify
`src/vinctor_service/local_http.py` (factory params, `_dispatch`, `_send_json`
status capture, `_observe` metrics, `/metrics` route, `_send_text`);
`src/vinctor_service/service_config.py` (`metrics` field + env);
`src/vinctor_service/service_runtime.py` (construct + pass `Metrics`);
`src/vinctor_service/cli.py` (`service serve --metrics`);
`src/vinctor_service/__init__.py` (export `Metrics`); test
`tests/test_metrics.py` (new) + `tests/test_local_http*`-style.

- [ ] **Step 1 — failing test** (`tests/test_metrics.py`):

```python
from vinctor_service.metrics import Metrics

def test_increment_and_render_prometheus_text() -> None:
    m = Metrics()
    m.increment("vinctor_http_requests_total", method="POST", path="/v1/enforce", status="200")
    m.increment("vinctor_http_requests_total", method="POST", path="/v1/enforce", status="200")
    m.increment("vinctor_enforce_decisions_total", decision="deny")
    out = m.render()
    assert "# TYPE vinctor_http_requests_total counter" in out
    assert 'vinctor_http_requests_total{method="POST",path="/v1/enforce",status="200"} 2' in out
    assert 'vinctor_enforce_decisions_total{decision="deny"} 1' in out
    assert out.endswith("\n")
```

- [ ] **Step 2 — run, expect FAIL** (no module).

- [ ] **Step 3 — `metrics.py`:**

```python
from __future__ import annotations
import threading

class Metrics:
    """Per-process, thread-safe counter set rendered as Prometheus text."""
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], int] = {}

    def increment(self, name: str, *, amount: int = 1, **labels: str) -> None:
        key = (name, tuple(sorted(labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + amount

    def render(self) -> str:
        with self._lock:
            items = sorted(self._counters.items())
        lines: list[str] = []
        seen_types: set[str] = set()
        for (name, labels), value in items:
            if name not in seen_types:
                lines.append(f"# TYPE {name} counter")
                seen_types.add(name)
            if labels:
                label_str = ",".join(f'{k}="{v}"' for k, v in labels)
                lines.append(f"{name}{{{label_str}}} {value}")
            else:
                lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"
```

  (Label values here are always server-controlled low-cardinality strings — method,
  fixed path, status code, permit/deny — so no Prometheus label-escaping is needed;
  do NOT pass user-controlled strings as labels.)

- [ ] **Step 4 — server plumbing** (`local_http.py`):
  - Add `metrics: Metrics | None = None` to both `create_v1_http_server` and
    `create_v1_http_handler` (thread it through).
  - Replace each `do_POST/do_GET/...` body with `self._dispatch("POST")` etc., and
    add:

```python
        def _dispatch(self, method: str) -> None:
            import time
            self._vinctor_start = time.monotonic()
            self._vinctor_status = None
            self._vinctor_decision = None
            self._vinctor_error = None
            try:
                _handle_request(self, method)
            finally:
                _observe(self, method)
```

  - In `_send_json`, after computing the response, record on the handler:
    `handler._vinctor_status = response.status_code`; if `isinstance(response.body,
    dict)`: `handler._vinctor_decision = response.body.get("decision")`,
    `handler._vinctor_error = response.body.get("error")`. (Do NOT record anything
    else from the body.)
  - Add `_observe` (closure, sees `metrics`/`access_log`): when `metrics is not
    None`, `metrics.increment("vinctor_http_requests_total", method=method,
    path=<parsed path>, status=str(status))` and, if decision in
    `("permit","deny")`, `metrics.increment("vinctor_enforce_decisions_total",
    decision=decision)`. (Access-log emission is Task 2.)
  - In `_handle_request`, add a `/metrics` branch near `/healthz`: if `path ==
    "/metrics"`: if `metrics is None` → 404 `{"error":"not_found"}`; elif method !=
    "GET" → 405; else send `metrics.render()` via a new `_send_text(handler, 200,
    body, content_type="text/plain; version=0.0.4")`.

- [ ] **Step 5 — config + serve wiring:** add `metrics: bool = False` to
  `ServiceRuntimeConfig`; `load_service_runtime_config` reads `VINCTOR_METRICS`
  (truthy); in `service_runtime`, `metrics = Metrics() if config.metrics else None`
  and pass it to `create_v1_http_server`; `vinctor service serve` gains
  `--metrics` (store_true) feeding the config. Export `Metrics` in `__init__`.

- [ ] **Step 6 — HTTP test:** a test that starts a handler with `metrics=Metrics()`,
  makes an enforce request, then `GET /metrics` returns 200 text containing
  `vinctor_http_requests_total` and `vinctor_enforce_decisions_total`; and that
  with `metrics=None`, `GET /metrics` → 404. Assert no key/token/grant_ref appears
  in the /metrics body.

- [ ] **Step 7 — run tests + full suite + ruff; commit** `feat(metrics): opt-in /metrics endpoint with in-process counters`.

---

### Task 2: opt-in structured access log

**Files:** `src/vinctor_service/local_http.py` (`access_log` param + `_observe`
log emission), `service_config.py` (`access_log` field + env),
`service_runtime.py` + `cli.py` (`--access-log`); test `tests/test_access_log.py`.

- [ ] **Step 1 — failing test:** start a handler with `access_log=True`, capture
  `sys.stderr`, make an enforce request, assert one JSON line is emitted with keys
  `{ts, method, path, status, latency_ms}` (+ `decision`/`error` for enforce) and
  that it contains NO agent key / token / grant_ref / raw value; and with
  `access_log=False`, assert NO line is emitted.

- [ ] **Step 2 — run, expect FAIL.**

- [ ] **Step 3 — implement:** add `access_log: bool = False` to both factories
  (thread through). Extend `_observe`: when `access_log`, build
  `line = {"ts": now().isoformat(), "method": method, "path": <parsed path>,
  "status": status, "latency_ms": round((time.monotonic()-start)*1000, 1)}`; add
  `decision`/`error` only if present (the coarse values already captured); emit
  `print(json.dumps(line, sort_keys=True), file=sys.stderr, flush=True)`. Only the
  whitelisted keys — never the request body, headers, or any id.

- [ ] **Step 4 — config + serve:** `ServiceRuntimeConfig.access_log: bool = False`;
  `VINCTOR_ACCESS_LOG` env; `service_runtime` passes `access_log=config.access_log`;
  `vinctor service serve --access-log`.

- [ ] **Step 5 — run tests + full suite + ruff; commit** `feat(logging): opt-in structured leak-free access log`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] Update `docs/deployment/operational-runbooks.md` (the suppressed-logging note)
  + `docs/next-actions.md` to record that opt-in access log + /metrics shipped, and
  that Docker publish / tagged release (needs credentials) remains the only open
  productionization item. (Small doc commit or fold into the PR.)
- [ ] Push branch, open PR (no merge; controller auto-merges after a final
  adversarial review per the march agreement).

## Notes
- **Default-off is the regression guard:** with neither flag, no /metrics route, no
  log lines, `log_message` still suppressed → byte-for-byte unchanged. Pin with a
  test that the default handler has no /metrics and emits nothing.
- **Leak discipline:** the ONLY things that may appear in metrics labels or log
  lines are: HTTP method, the parsed request path (fixed route set), the HTTP
  status code, and the coarse `decision`/`error` codes already in the response
  body. Never a key, token, grant_ref, agent/workspace id, boundary id, or body.
- Counters are per-process/ephemeral (reset on restart) — standard for a
  Prometheus-scraped counter; document if asked.
