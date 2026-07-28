# Changelog

Notable changes to `vinctor-core`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was adopted on 2026-07-17. Releases before `0.5.0` are listed by
version and date only and are not reconstructed change-by-change. Tags are
provenance only where the published artifact was verified against their source
tree. PyPI `0.4.0` could not be matched to a source tree, so it deliberately has
no verified tag; the public mirror's pre-existing `v0.4.0` tag and release must
not be used as provenance.

## [0.6.0] - 2026-07-28

### Breaking changes

- **Re-read every grant you have issued.** `create_repository` moved from
  `github/_/repo` to `github/{owner}/_/repo`. Any existing
  `write:github/<org>/*` grant therefore acquired repository-creation rights it
  did not previously carry. Revoke or narrow grants whose wildcard was not
  intended to authorize repository creation.
- **Fresh databases require a boundary by default.** SQLite now creates
  `agent_enforcement_settings.require_boundary` with `DEFAULT 1`, and Postgres
  with `DEFAULT TRUE`. The repository uses that database-owned default only
  when no workspace or agent override exists. Existing databases retain their
  old `0/FALSE` column default and every stored value; migration does not turn
  the mandate on. A new install denies a PEP that omits
  `X-Vinctor-Boundary-Id`.
- **Postgres requires `psycopg[binary]>=3.2` plus a usable
  `Connection.cancel_safe`.** Vinctor checks
  `psycopg.capabilities.has_cancel_safe(check=True)` at startup. System-libpq
  installs are the likely breakage point; the binary extra may already bundle
  a sufficient libpq. SQLite is unaffected.
- Conformance `fixtures_version` is now a 64-character SHA-256 digest over the
  four generated family files, not the integer `1`. The integer stayed fixed
  through semantic canon changes, so adapters could accept stale fixtures.
  Every adapter in this release is re-vendored to the digest.

### Known limits

- `/v1/observe` still rejects the body emitted by the Claude and Codex hooks,
  so their unmapped calls are not reported centrally (PKA-192).
- Malformed enforce requests intentionally produce no audit row under
  [ADR 0008](docs/decisions/0008-auditing-pre-grant-evaluation-rejections.md)
  (PKA-186).
- `vinctor-mcp-pep` is not yet covered by the shared validation harness
  (PKA-124).
- The default posture is tighter, but classifier coverage is not complete.
  Bare-remote `git push` (PKA-182), `mv`/`cp`/redirect handling for sensitive
  paths (PKA-183), and MCP server-name routing (PKA-189) remain queued for the
  next release. Do not read default-closed as complete mediation coverage.

### ⚠️ Migration

- **`/healthz` no longer reports the durable store — if you use it as a
  readiness or traffic gate, switch that gate to `/readyz`.** On the Postgres
  backend `/healthz` used to return `503` while the durable connection was
  unrecoverable, so a load balancer, container healthcheck, or `depends_on`
  condition pointed at `/healthz` will now keep sending traffic to an instance
  whose database is down. `/healthz` is process liveness only: it performs no
  database operation on any backend and answers `200` for as long as the
  process can serve. `/readyz` is the traffic gate and is unchanged in meaning.
  The shipped Compose files already probe `/readyz`; the published image's own
  `HEALTHCHECK` did not — see the next entry.

  This is a deliberate fix, not a regression: the deployment guidance told
  operators to wire `/healthz` to the Kubernetes **liveness** probe, so a
  Postgres outage failed liveness on every pod simultaneously and restarted the
  entire fleet — amplifying the outage and destroying the diagnostic state an
  operator needs.

- **The published image's `HEALTHCHECK` now probes `/readyz` instead of
  `/healthz`, so container health tracks the durable store.** Anything gating
  on the image's own healthcheck — `docker run`, Swarm, ECS, Nomad, or a
  compose file without its own `healthcheck:` block — previously reported
  `healthy` through a total store outage and will now report `unhealthy`. If
  you relied on the container staying healthy while the database was down, that
  was the bug. Its `--timeout` moves from 3s to 5s so it exceeds the endpoint's
  own probe bound.

- **`create_v1_http_server` / `create_v1_http_handler` no longer accept a
  `liveness_check` argument** (breaking for embedders — both are public API).
  It existed only to inject a store probe into `/healthz`, which is the
  behavior change above; callers passing it must drop it. No caller outside
  this repository is known.

### Changed

- `/readyz` runs its backend probe under an explicit deadline on a
  single-flight worker. A hung backend socket now answers `unavailable` at the
  bound instead of blocking with the socket, and a probe flood produces at most
  one *concurrent* backend query — single-flight bounds concurrency, not query
  rate, and there is no result cache, so against a healthy store each request
  still costs one backend round-trip. Responses are unchanged and still
  disclose no DSN, path, exception, or backend identity.
- New `VINCTOR_READINESS_PROBE_TIMEOUT_SECONDS` (default `2.0`) sets that
  bound. Raise it if your store is slow but healthy: the probe runs the
  idempotency-readiness queries as well as `SELECT 1`, so a large
  `idempotency_results` table can exceed the default and drain the busiest
  instance. Non-positive, unparseable, `nan`, and `inf` values fall back to the
  default — the probe can be retuned but never switched off. On Postgres the
  same value bounds the probe's connection (`connect_timeout`,
  `statement_timeout`).
- A readiness worker blocked inside the backend call is now replaced instead of
  wedging `/readyz`. The worker was restarted only when it was not alive, and a
  worker blocked in a socket read is alive: every later probe waited its
  deadline and returned `503` while the backend was never asked again, so one
  stuck connection drained the instance until it was restarted even after the
  database recovered. Replacements are capped and reaching the cap is reported
  on stderr.
- **Postgres readiness uses connections of its own**, with `connect_timeout`,
  TCP keepalives, `statement_timeout` and (on libpq 12+) `tcp_user_timeout`;
  an expired probe is cancelled and its connection discarded. Readiness no
  longer takes the serialized connection lock that every enforce request needs,
  so a slow probe cannot stall request traffic and a wedged one cannot pin the
  process's connection. **Size `max_connections` for up to 5 extra sessions per
  service process** — one in steady state, but probes overlap while a wedged
  one is being replaced, and the cap on abandoned workers is 4.
- Readiness recovery no longer waits for a wedged call to be answered. While any
  worker is abandoned, a reclaimer thread keeps cancelling the calls that blew
  the bound; a cancel travels over a new connection, so the instant the store is
  reachable again the wedged calls end, their slots return and `/readyz` answers
  `200`. Cancelling never runs on a request thread or on a replacement probe's
  thread, and Vinctor stops waiting for it at its own deadline rather than
  relying on the driver to honour one — psycopg discards `cancel_safe`'s timeout
  below libpq 17 and falls back to a blocking `PQcancel`.
- **`/readyz` no longer answers `200` through a dead serving connection.** The
  readiness probe checked only its own connection plus a cached "connection
  usable" flag, and that flag turns false only once something has *tried* to use
  the serving connection — so between a backend dying and the next enforce
  request, readiness reported the instance healthy while it could not serve a
  request. It now also runs a `SELECT 1` on the serving connection, which is
  additionally what reconnects it: a drained instance receives no enforce
  traffic, so without this a single terminated backend removed a process from
  rotation permanently against a healthy database.
- Shutdown after a store outage no longer raises. Releasing the writer
  attestation to a backend that has already gone cannot be performed and cannot
  matter; it no longer aborts teardown, and `close()` is repeatable.
- **⚠️ The Postgres backend now requires a bounded query cancellation —
  `Connection.cancel_safe()`, which needs psycopg 3.2+ *and* libpq 17+ — and
  refuses to start without it**, naming the detected versions. Without it a
  wedged readiness probe can never be reclaimed and `/readyz` latches at `503`
  after the database has recovered. The check asks
  `psycopg.capabilities.has_cancel_safe(check=True)` rather than reading a
  version number, because either half alone is not the requirement: psycopg 3.1
  against libpq 18 passes a libpq check and still has no such method.
  `pyproject.toml` can pin psycopg but cannot express a libpq floor, and
  `psycopg[binary]>=3.2` pins the driver, not the libpq it happens to bundle —
  so the startup check is what enforces it. **SQLite is unaffected.**
- SQLite readiness now interrupts a statement that has outlived the bound
  (`sqlite3.Connection.interrupt()`), instead of waiting out the 5s busy
  timeout under a 2s readiness bound. **Up to 5 of the 8 pooled connections may
  be held by readiness while probes are wedged** (one before this release), so
  a wedged store reduces enforce concurrency until they are interrupted.
- Shutdown no longer closes a database handle underneath an in-flight readiness
  probe (observed as `sqlite3.ProgrammingError: Cannot operate on a closed
  database`). `close()` joins the worker only briefly, so the connection the
  probe borrowed is now left to the probe to dispose of.

### Added

- `vinctor operator keys create pep --pep-id <id>` mints a PEP
  (resource-server) key. A PEP authenticates to `POST /v1/enforce/delegated`
  with an `X-PEP-Key` header, and nothing shipped could produce that secret:
  `operator keys` was list/revoke/rotate only, `vinctor local start` mints only
  workspace and agent keys, and there is no HTTP route for it — so the published
  route answered `401 valid X-PEP-Key header is required` with no supported way
  to get past it. Unlike `keys rotate pep`, `create` leaves existing PEP keys
  active, so standing up a second PEP does not lock out the first. The key and
  its new `key_created` control audit event commit as one transaction, like
  every other key operation.
- Proxy-aware HTTP rate-limit source resolution via opt-in
  `VINCTOR_TRUSTED_PROXIES`, with right-to-left `X-Forwarded-For` validation and
  the existing socket-peer behavior unchanged by default.
- A CI gate asserts that every `VINCTOR_*` name in the shipped README exists in
  the shipped wheel. A README that names an environment variable no shipped code
  reads is worse than a missing feature: the operator sets it, nothing errors,
  and they believe the control is on. Names owned by another component (the
  PEP's `VINCTOR_ENFORCEMENT_MODE`) are exempted explicitly, and an exemption
  fails the gate once the name does appear, so it cannot go stale.
- A `bare-install` CI job builds the wheel, installs it into a clean virtualenv
  with **no** extras, and then runs both console scripts, imports every module
  in the distribution, and runs the SQLite service demo. The existing jobs all
  install `.[dev,postgres]`, so none of them could see the configuration a plain
  `pip install vinctor-core` produces — which is how the defect below shipped on
  a green CI. The job fails if psycopg, the MCP SDK, or PyJWT turn out to be
  installed, so it cannot quietly stop testing a bare install.

### Documentation

- The README's Local Prototype Quickstart now works against `vinctor local
  start` as written. It previously requested `execute:ci/test`, which is outside
  the issuable-scope bounds `local start` itself sets (`write:repo/feature/*`),
  so approval failed with `scope_outside_issuable_bounds`; the bounds were also
  attributed to the demo policy file rather than to the launcher. The recovery
  step it pointed at — `operator policy apply --file
  docs/examples/local-demo-policy.yaml` — is unreachable from a `pip` install,
  because `docs/` is not in the wheel.
- Every README reference to `docs/`, `demo/`, `tools/`, and `make` now points at
  the public repository or is marked as requiring a source checkout. None of
  those directories are in the wheel, so all of them were dead links for anyone
  who installed from PyPI.
- The README documents that **disabling a boundary is not a kill switch**: the
  boundary travels in the caller-controlled `X-Vinctor-Boundary-Id` header, so
  the same call omitting the header is permitted while the one presenting it is
  denied `boundary_unavailable`. `operator require-boundary enable` is the
  control that makes the boundary mandatory (`boundary_required`); it defaults
  to off and is settable only through `--db`.
- The README states the fail-closed audit property directly: an enforce whose
  durable audit write fails returns `503` with **no** `decision` field, on
  permit, deny, and destructive cases alike, and writes nothing. It is a
  property of the enforce path, not a setting — `VINCTOR_AUDIT_SINK_REQUIRED`
  governs the anchor/export sinks only.
- Retired coverage claims are gone from every shipped surface, not only the
  README. `vinctor demo block` still printed "Vinctor authorizes mediated tool
  calls; it is not a sandbox", and `docs/cli-reference.md` still described a
  grant as what "each tool call is checked against". The hero image's alt text
  still read "permits or denies each AI-agent action" — the wheel ships no
  `docs/`, so for any reader whose renderer does not fetch the image, that alt
  string *is* the hero text. The gate enforcing this now scans `src/**/*.py`,
  `docs/**/*.md`, and `docs/**/*.svg` from a repo root resolved off the test
  file, instead of two paths relative to the working directory.
- The enforce body is documented as a single `(action, resource)` pair again. A
  draft of this section described "one or more `(action, resource)` effects";
  no released artifact accepts that. `POST /v1/enforce` rejects a list action
  with `400 action must be a non-empty string` and an `effects` key with `400
  unexpected field: effects`, and `grep -rn effects src/` has no hits.
  Multi-effect mapping exists only on adapter default branches, which postdate
  every tag and every publish.
- The authorization context names the requesting agent and the time of the
  request again, so the prose, the Decision Model list, and the hero image
  agree. Each independently changes the outcome: swapping only the agent key
  turns a permit into `403 grant is not accessible for this request`, and
  crossing only the grant's expiry turns it into `decision: deny`,
  `grant_expired`.
- The audit sentence no longer says that calls which "complete enforcement
  evaluation produce an audit record" — ambiguous exactly where it matters,
  since on an audit-write failure the verdict *is* computed and no record is
  written. It now says every verdict a caller receives has been recorded, and
  links to "No audit row, no decision".

### Fixed

- **`vinctor-mcp-server` without the `[mcp]` extra now names the missing extra
  rather than a missing environment variable.** The SDK check ran *after*
  configuration validation, so a bare install answered `error:
  VINCTOR_MCP_ENDPOINT is required`. The documented `error: MCP SDK is required
  to run vinctor-mcp-server. Install with vinctor-core[mcp].` surfaced only once
  both `VINCTOR_MCP_ENDPOINT` and `VINCTOR_MCP_WORKSPACE_KEY` were set — that
  is, only after the operator had finished configuring a command that could not
  start under any configuration. The SDK check now runs first. `--help` still
  exits `0` without the extra, since argument parsing precedes startup, so a
  passing `--help` is not evidence the server can run.
- **A default `pip install vinctor-core` could not run any command.**
  `0.5.0`'s idempotent-replay encryption work put `import psycopg` at the module
  scope of the Postgres backend, which `vinctor_service` imports eagerly, so
  `import vinctor_service` and every `vinctor` subcommand died with
  `ModuleNotFoundError: No module named 'psycopg'` — including the entire SQLite
  path, which needs no driver at all. `vinctor-core[postgres]` was in practice
  the only working install. Postgres is optional again, and stays optional: the
  backend modules import psycopg's exception types through a shim that degrades
  to unraisable placeholders, and the driver itself is loaded only when
  `connect_postgres` opens a connection. Selecting Postgres without the extra
  still fails closed and now does so on one line —
  ``error: Postgres support requires `pip install vinctor-core[postgres]` ``,
  exit code 5 — instead of dumping a traceback and internal paths.
  `connect_postgres` raises `PostgresDriverUnavailable`, a `RuntimeError`
  subclass, so callers catching `RuntimeError` are unaffected.

## [0.5.0] - 2026-07-17

The first release since PyPI `0.4.0` (2026-07-13; no verified source tag):
28 merged pull requests,
carrying the whole 2026-07-14 Postgres / OIDC / OTLP / RBAC wave (ADRs
0012–0018) and the 2026-07-15 hardening.

### ⚠️ Migration

- **`connect_sqlite` is now the only supported way to open a Vinctor SQLite
  database.** Code that passed its own `sqlite3.connect(...)` to a service or
  repository must switch to `connect_sqlite`; `require_serialized` rejects a raw
  `sqlite3.Connection`. Two wrappers over one physical connection means two
  locks and silent data loss, so this is enforced rather than advised.
- **Databases are now opened with `journal_mode=WAL`.** WAL — unlike the other
  journal modes — is a property of the database *file*, so once a database has
  been converted, later connections come up in WAL too. Neither half of that is
  a guarantee: if WAL cannot be enabled (some network filesystems cannot support
  it) the service warns on stderr and continues on whatever journal mode it got,
  and the setting persists in the file rather than being permanent — a later
  connection can switch it. WAL is required for concurrency, not for
  correctness.
  - **Use `vinctor operator storage backup`.** It reads through the SQLite
    backup API, so it captures committed transactions still resident in the
    `-wal` sidecar and writes one self-contained file.
  - **Do not copy a live database's files.** While a WAL database is in use,
    committed rows can be resident in a `<db>-wal` sidecar while the main file
    looks untouched — so copying the main file alone yields a database that
    opens cleanly, queries cleanly, and is quietly missing rows, with no error
    at copy time or read time. Copying the sidecars as well does **not** fix
    that: files that are changing cannot be captured as an atomic snapshot by
    copying them one after another. If you must move files, stop or quiesce the
    service and checkpoint first (`PRAGMA wal_checkpoint(TRUNCATE)`).

  > *Corrected 2026-07-17.* The published 0.5.0 artifact carries an earlier
  > wording of this note that called the conversion "permanent", stated a WAL
  > database is always three files, and offered "include the `-wal`/`-shm`
  > sidecars" as a way to copy a live database. The first two overstate; the
  > third is unsafe advice, and copying a live database that way can lose data
  > rather than preserve it. See
  > [Operational Runbooks](docs/deployment/operational-runbooks.md) for the full
  > version.

### Added

- **Postgres full control plane** (ADR 0018) — every SQLite repository gained a
  Postgres twin and `PostgresV1Service` exposes the identical surface: storage
  (#125), runtime (#128), boundary + enforcement settings (#130), policy parity
  (#134), control plane (#139).
- **OIDC bearer authentication and role mapping** (ADR 0016) — #136.
- **Workspace-scoped read-only auditor key** (ADR 0014) — #133.
- **Service-operator view for unattributed authentication failures**
  (ADR 0015) — #135.
- **Best-effort OTLP/HTTP audit export** (ADR 0012) — #131, with batching #138.
- **Versioned policy rollback** (ADR 0013) — snapshot-based exact rollback
  through the serialized policy transaction — #132.
- **Storage readiness probe** (ADR 0017) — `/readyz` performs a real backend
  check — #137.
- **Action taxonomy** — the canonical (tool → action, resource) mapping shared
  by the PEP adapters — #118.
- **Observe / infer / simulate surfaces** — observe + infer (#126), simulate
  mode (#127), infer/simulation UX (#129).
- **`operator audit list --reason`** filter — #145.
- **`require-pop` enable warning** — #143.

### Changed

- **Bounded SQLite connection pool** (#150) — the local HTTP runtime now leases
  one of a bounded pool of independent connections for the duration of each
  request, replacing the process-global lock that serialized every DB-touching
  request. Authentication lookups, request parsing and response writing now run
  in parallel; write transactions still serialize (each takes SQLite's write
  reservation via `BEGIN IMMEDIATE`, which is what keeps the audit hash chain
  gapless across connections). Connections are opened with WAL and a busy
  timeout — see Migration above.
- **`SerializedSQLiteConnection`** (#149) — a single ownership root for SQLite
  connections. See Migration above.
- Gradual-rollout guide — #146.

### Fixed

- **Postgres key-rotation nested-check race** (#152) — `info.transaction_status`
  describes the connection, not the calling thread, so reading it before taking
  the connection lock mistook a peer thread's open transaction for caller
  nesting and rejected a legitimate concurrent rotation with "key rotation
  cannot run inside an open transaction". The lock is now taken first, matching
  the SQLite rotation scope.
- **WAL storage lifecycle** (#150) — `restore` / `reset` / `backup` now
  checkpoint the source WAL and remove `-wal` / `-shm` sidecars around the
  atomic file replace. A stale sidecar left beside a freshly swapped database
  can be replayed against it, because SQLite does not bind a WAL to a specific
  database file.
- Postgres audit-verify parity — #144.
- Postgres control-plane close (#141), proposal evidence expectations (#142),
  and a service-runtime conflict marker (#140).

### Security

- **TIER-3 security hardening** (#148) — 16 fixes closing roughly 20 findings
  from two independent reviews, over 6 adversarial review rounds: no-disclosure
  sanitization of agent-facing denials, PoP replay fail-closed, delegated
  workspace binding, audit seq-ordering and cross-check, atomic policy-apply and
  grant-decision CAS.

## Earlier releases

Not reconstructed here. PyPI `0.4.0` is listed as a published artifact, not as a
verified git tag:

| Version  | Date       |
| -------- | ---------- |
| `0.4.0`  | 2026-07-13 |
| `v0.3.0` | 2026-07-13 |
| `v0.2.1` | 2026-07-12 |
| `v0.2.0` | 2026-07-11 |
| `v0.1.0` | 2026-06-25 |
