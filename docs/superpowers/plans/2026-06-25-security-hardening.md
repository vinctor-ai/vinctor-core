# Q — security hardening (release gate HIGH + chosen MEDIUM/LOW) (Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development.

**Goal:** Fix the security findings selected for v0.1.0: the release-gating HIGH
(pre-auth DoS) plus the cheap high-value MEDIUM/LOW items. (Deferred to v0.1.1: audit
SQL pushdown, PoP per-token partition.) Repo
`/Users/taeheon/dev/agent-authority/vinctor-core`, venv `.venv/bin/...`, branch
`feat/security-hardening`, main human-merge-only. Commit trailer ends with
`Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. stdlib only;
`ruff check` only; keep ALL existing tests green.

---

### Task 1: pre-auth DoS — bounded body read + handler timeout + pop_skew parse-once (HIGH gate)

**Files:** `src/vinctor_service/local_http.py` (`_read_json_body` ~549-565, any
`_read_optional_json_body`, `V1Handler` class ~101, the per-request `pop_skew_seconds=
int(os.environ...)` ~333); test `tests/test_local_http*` / a new test.

- [ ] **Step 1 — failing tests:**
  - a POST with `Content-Length` far larger than a small cap (e.g. 10_000_000) is
    rejected with **413** (or a clean 400) BEFORE the body is read — and the handler
    does NOT attempt to buffer it; assert the response + that no huge read happens.
  - a POST with a **negative** `Content-Length` (e.g. `-1`) is rejected cleanly (NOT
    `rfile.read(-1)` draining the socket).
  - a normal small JSON body still works (regression).
  - `V1Handler.timeout` is set to a finite value (assert the class attribute is not
    None).
  - an invalid `VINCTOR_POP_SKEW_SECONDS` (e.g. "30s") does NOT 500 the delegated
    path per request (it is validated once / falls back to the documented default).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:**
  - Add a module-level `MAX_BODY_BYTES` (small, e.g. `64 * 1024` — all legitimate
    bodies are tiny JSON). In `_read_json_body` (and `_read_optional_json_body` if
    separate): after parsing `length`, if `length < 0` or `length > MAX_BODY_BYTES`
    return a clean `413` (`{"error":"payload_too_large", ...}`) (negative → 400/413,
    not a read); then `raw_body = handler.rfile.read(min(length, MAX_BODY_BYTES))`.
  - Set `V1Handler.timeout = 15` (class attribute) so the stdlib server reaps
    idle/slow/blocked connections (defeats the slow-loris / blocked-read thread-pin).
  - pop_skew: stop calling `int(os.environ.get("VINCTOR_POP_SKEW_SECONDS", ...))`
    per-request unguarded. Parse + validate ONCE (at server/handler construction, or
    a guarded helper) so an invalid value yields a clean startup error or falls back
    to the documented default (30) rather than a per-request 500. Keep the same
    default + behavior for valid values.
- [ ] **Step 4 — run tests + full suite + ruff; commit** `fix(security): bound pre-auth request body + handler timeout + parse pop_skew once`.

---

### Task 2: close the cross-tenant grant existence oracle + normalize naive expires_at (MEDIUM + INFO)

**Files:** `src/vinctor_service/v1_enforce.py` (`enforce_v1_contract` ~57-79 AND
`delegated_enforce_v1_contract` ~168-193), `src/vinctor_service/sqlite.py`
(`_grant_from_row` ~1500-1509); tests `tests/test_*enforce*` / `tests/test_delegated_*`.

- [ ] **Step 1 — failing tests:**
  - on BOTH the direct and delegated enforce paths, a **nonexistent** grant_ref and an
    **existing-but-foreign** grant_ref (wrong workspace and/or wrong agent) produce an
    **identical caller-facing response** — same status (use **403 forbidden**) and the
    same generic message (no `grant_ref` echoed, no "does not exist" vs "does not
    belong" distinction). A probe cannot tell existence apart.
  - the operator-only mismatch audit (`REASON_AGENT_GRANT_MISMATCH`) is STILL written
    for the genuine existing-but-foreign case, and is attributed to the CALLER's own
    authenticated workspace (direct: the agent-key workspace; delegated: `trusted_ws`,
    NOT the caller-asserted workspace), so a probe cannot write into a victim
    workspace's audit trail. The nonexistent case writes no mismatch audit.
  - a grant row with a tz-naive `expires_at` is coerced to UTC so the enforce
    comparison cannot `TypeError` (defense-in-depth; fails-closed today but normalize
    anyway).
- [ ] **Step 2 — run, expect FAIL.**
- [ ] **Step 3 — implement:**
  - Collapse the `grant is None` branch and the workspace/agent-mismatch branch into a
    single identical caller-facing `_pre_audit_error(403, "forbidden", <generic msg
    with no grant_ref>)` on both paths. Keep the `_record_rejection(... reason_code=
    REASON_AGENT_GRANT_MISMATCH ...)` ONLY for the real existing-but-foreign case,
    attributed to the caller's own workspace. (Preferred: resolve/scope the grant to
    the caller's trusted workspace first; if absent OR not owned → the one generic
    403.) Do not echo the supplied grant_ref in the message.
  - In `_grant_from_row`, if `expires_at.tzinfo is None`, set it to UTC
    (`value.replace(tzinfo=UTC)`).
  - Update the api-contract / reason-code docs note if they state enforce returns 404
    `grant_not_found` (it now returns the uniform 403) — fold a one-line doc fix in.
- [ ] **Step 4 — run tests + full suite + ruff; commit** `fix(security): uniform fail-closed response for unknown/foreign grant (close existence oracle) + normalize naive expires_at`.

---

### Task 3: container non-root + supply-chain pinning + bundled-compose posture (MEDIUM)

**Files:** `Dockerfile`, `compose.yaml` (top-level), `.github/workflows/release.yml`,
`.github/workflows/ci.yml`, `docs/deployment/operational-runbooks.md` +
`deploy/preview/Caddyfile` (if present). Config — validate, do not break.

- [ ] **Step 1 — Dockerfile non-root:** add a system user and run as it:
  `RUN useradd --system --uid 10001 vinctor` (or adduser), `mkdir -p /data &&
  chown vinctor:vinctor /data`, and `USER vinctor` before `CMD`. Keep the image
  functional (`vinctor service serve`). Document a `chown` note for pre-existing named
  volumes in the runbook.
- [ ] **Step 2 — pin third-party GitHub Actions by commit SHA:** for EACH `uses:
  <action>@<tag>` in release.yml + ci.yml, RESOLVE the real commit SHA via
  `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` (gh is available) and replace with
  `<action>@<full-sha>  # <tag>`. Cover actions/checkout, actions/setup-python,
  actions/upload-artifact, actions/download-artifact, softprops/action-gh-release,
  docker/login-action, docker/metadata-action, docker/build-push-action, and
  pypa/gh-action-pypi-publish (resolve the `release/v1` BRANCH to its current commit
  SHA — `gh api repos/pypa/gh-action-pypi-publish/git/ref/heads/release/v1`). Use REAL
  resolved SHAs only — never invent one.
- [ ] **Step 3 — base image digest (best-effort):** try `docker manifest inspect
  python:3.11-slim` (or `docker buildx imagetools inspect`) to get the digest and pin
  `FROM python:3.11-slim@sha256:<digest>  # 3.11-slim`. If docker is unavailable /
  digest unresolvable, LEAVE `FROM python:3.11-slim` with a `# TODO: pin by digest`
  comment — do NOT guess a digest.
- [ ] **Step 4 — bundled compose posture + proxy body limit:** in the top-level
  `compose.yaml`, bind host-local by default — change the port mapping to
  `"127.0.0.1:8765:8765"` (so `docker compose up` + `curl localhost:8765` still works
  but the raw server is NOT network-exposed) and add a comment that network exposure
  should go through a reverse proxy. Add a proxy body cap where a proxy is documented:
  `request_body { max_size 64KB }` in `deploy/preview/Caddyfile` (if present) and a
  `client_max_body_size 64k;` note in the nginx snippet in operational-runbooks.md.
- [ ] **Step 5 — validate:** `.venv/bin/python -c "import yaml; yaml.safe_load(open('compose.yaml'))"` and the two workflow YAMLs parse; full suite + ruff still green (config changes don't affect tests). Commit `chore(security): non-root container, SHA-pinned actions, host-local bundled compose + proxy body caps`.

---

## Final
- [ ] Full suite + `ruff check src/ tests/` green; all YAML parses.
- [ ] Update `docs/next-actions.md` + `docs/threat-model.md` (note the body cap +
  timeout; record audit-SQL-pushdown + PoP-per-token-partition + base-image-digest as
  v0.1.1 follow-ups; note the SQLite file is secret-bearing). Fold into the PR.
- [ ] Push branch, open PR (no merge; controller auto-merges after a final adversarial
  review per the march agreement).

## Notes
- Task 2 is the most security-sensitive (it changes the enforce response contract for
  unknown/foreign grants 404→403). It MUST stay fail-closed (never a permit) and must
  not leak existence; it gets a final adversarial review.
- Deferred to v0.1.1 (NOT in this slice): audit list/export SQL pushdown, PoP replay
  per-token partition, pop_secret encryption at rest, auth-failure rate limiter,
  SBOM/provenance + HEALTHCHECK.
