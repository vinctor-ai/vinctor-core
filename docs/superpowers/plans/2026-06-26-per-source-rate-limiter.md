# Per-source request rate limiter (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** An OPT-IN, pre-auth, per-source request rate limit on the HTTP service to
blunt request-volume floods (complements the existing pre-auth body cap +
HANDLER_TIMEOUT). Default OFF → byte-for-byte backward compatible. stdlib only.
Repo `/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`,
branch `feat/per-source-rate-limiter`, main human-merge-only (controller merges after
review). Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. `ruff check` only.

## Design decisions (autonomous, single-purpose — documented for founder override)
- **Source key = client IP** (`handler.client_address[0]`). Right notion of "source"
  for the single-node preview. LIMITATION (document, don't fix): behind a reverse
  proxy every request appears from the proxy IP and shares one bucket; honoring a
  trusted `X-Forwarded-For` is a deferred follow-up.
- **Algorithm = fixed-window counter**, in-memory, per-process, thread-safe
  (`threading.Lock`), memory-bounded. Mirrors `PopReplayCache` / `AuthFailureAuditThrottle`.
- **Config = one env var** `VINCTOR_RATE_LIMIT_PER_MINUTE` (int). Unset / ≤0 /
  unparseable → DISABLED (limiter is `None`, no behavior change). Window fixed at 60s
  (the var name says per-minute; no second knob — YAGNI).
- **Over-limit response = HTTP 429**, generic JSON body `{"error": "rate_limited"}`,
  no other detail (no disclosure). Optional `Retry-After: 60` header.
- **Pre-auth**: checked at the TOP of `do_POST`/`do_GET`, BEFORE routing / body read /
  auth, so it protects the unauthenticated surface.
- **Fail-OPEN** (it is an availability tool, not an authz gate): if the limiter is
  disabled OR `allow()` raises, the request proceeds. A limiter that fail-closes (or
  that denies because its source table is full) is itself a DoS vector.
- **Not audited**: like the body-cap rejection, a pre-auth volume rejection has no
  workspace context and is volume noise — do NOT write an audit event.

---

### Task 1: FixedWindowRateLimiter + pre-auth HTTP wiring

**Files:**
- Create: `src/vinctor_service/ratelimit.py`
- Create: `tests/test_ratelimit.py`
- Modify: `src/vinctor_service/local_http.py` (add `_resolve_rate_limit()` near
  `_resolve_pop_skew_seconds()` ~line 549; build one limiter in the handler closure
  near `pop_skew_seconds = _resolve_pop_skew_seconds()` ~line 110; add a
  `_check_rate_limit` gate called first in `do_POST` and `do_GET` ~line 116-119; a 429
  responder reusing the existing JSON-response writer).
- Modify: `tests/` HTTP test module that exercises the local service (find the existing
  one, e.g. `test_local_http*.py`) — add disabled-default + over-limit + generic-body tests.

- [ ] **Step 1 — recon**: read `local_http.py` `_resolve_pop_skew_seconds` (the parse-
  once pattern), the `V1Handler` closure + how `pop_skew_seconds` is captured, `do_POST`/
  `do_GET`, the `_read_json_body` 413 path (`MAX_BODY_BYTES`, ~line 596) and the helper
  that writes a `V1HttpResponse`/JSON+status (mirror it for 429). Read `pop.py`
  `PopReplayCache` for the lock/prune idiom. Confirm `client_address` is available on the
  handler.
- [ ] **Step 2 — failing unit tests** (`tests/test_ratelimit.py`), inject `now` as a
  param (no wall-clock; pass floats):
  - allows up to `max_requests` within the window, denies the `(max+1)`th (same source).
  - window reset: after `now` advances ≥ `window_seconds`, the source is allowed again.
  - per-source isolation: source A at its limit does not affect source B (fresh → allowed).
  - memory bound + fail-open: with a tiny `max_sources`, once full, a brand-new source is
    ALLOWED (fail-open), and expired entries are pruned first; existing tracked sources
    still enforce their limit.
  - (thread-safety) a `threading.Lock` guards mutation — assert sequential correctness;
    a concurrency smoke (N threads × M calls) stays within `max_requests` per source.
- [ ] **Step 3 — run, expect FAIL.**
- [ ] **Step 4 — implement `ratelimit.py`:** `class FixedWindowRateLimiter` with
  `__init__(self, *, max_requests: int, window_seconds: int = 60, max_sources: int = 10000)`
  and `allow(self, source: str, now: float) -> bool`. Under the lock: prune expired
  windows; if `source` absent and table at `max_sources` → return True (fail-open, no
  insert); if window expired/new → reset `(window_start=now, count=1)` → True; elif
  `count < max_requests` → `count += 1` → True; else → False (do NOT keep incrementing).
  `max_requests <= 0` is a programming error (the caller only builds the limiter when the
  configured value is positive). stdlib only.
- [ ] **Step 5 — failing HTTP tests**, then wire `local_http.py`:
  - `_resolve_rate_limit() -> int | None`: read `VINCTOR_RATE_LIMIT_PER_MINUTE`; return a
    positive int or `None` (unset/≤0/unparseable → None). Parse ONCE (alongside
    `_resolve_pop_skew_seconds()`), not per request.
  - In the handler-closure scope build `rate_limiter = FixedWindowRateLimiter(
    max_requests=_n, window_seconds=60) if _n else None` (captured like `pop_skew_seconds`).
  - `_check_rate_limit(self) -> bool`: if `rate_limiter is None` return True; else
    `try: ok = rate_limiter.allow(self.client_address[0], time.time())` `except Exception: return True`
    (fail-open); if not ok → write 429 `{"error":"rate_limited"}` (+ `Retry-After: 60`) and
    return False. Call it as the FIRST line of both `do_POST` and `do_GET`; if it returns
    False, return immediately (no routing, no body read).
  - HTTP tests: (a) default (env unset) → limiter None → existing behavior byte-for-byte,
    no 429 ever; (b) `VINCTOR_RATE_LIMIT_PER_MINUTE=2` → 3rd rapid request from the same
    client → 429 with the generic body and nothing else disclosed; (c) GET (e.g. /healthz)
    is gated too.
- [ ] **Step 6 — full suite + ruff; commit** `feat(security): opt-in per-source request rate limiter (pre-auth, fail-open, default off)`.

## Final
- [ ] Full suite + `ruff check src/ tests/` green.
- [ ] `docs/next-actions.md`: move "per-source request rate limiter" from the v0.1.1
  still-deferred security list to shipped; `docs/cli-reference.md` (or the env/config doc):
  document `VINCTOR_RATE_LIMIT_PER_MINUTE` (default off, per-source-IP, 429, pre-auth,
  proxy caveat). Fold into the PR.
- [ ] Controller runs a final adversarial review before merge. Push branch + open PR.

## Invariants
- Default OFF = byte-for-byte unchanged (no env → no limiter → no new code path taken).
- Fail-OPEN everywhere (disabled, exception, or table-full → request proceeds).
- 429 body discloses nothing beyond `rate_limited`.
- No DB/schema change (in-memory only). stdlib only.
