# Changelog

Notable changes to `vinctor-core`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was adopted on 2026-07-17. Releases before `0.5.0` are listed by
version and date only and are not reconstructed change-by-change — see the
GitHub Releases page and the git tags for those.

## [Unreleased]

### Added

- Proxy-aware HTTP rate-limit source resolution via opt-in
  `VINCTOR_TRUSTED_PROXIES`, with right-to-left `X-Forwarded-For` validation and
  the existing socket-peer behavior unchanged by default.

## [0.5.0] - 2026-07-17

The first release since `v0.4.0` (2026-07-13): 28 merged pull requests,
carrying the whole 2026-07-14 Postgres / OIDC / OTLP / RBAC wave (ADRs
0012–0018) and the 2026-07-15 hardening.

### ⚠️ Migration

- **`connect_sqlite` is now the only supported way to open a Vinctor SQLite
  database.** Code that passed its own `sqlite3.connect(...)` to a service or
  repository must switch to `connect_sqlite`; `require_serialized` rejects a raw
  `sqlite3.Connection`. Two wrappers over one physical connection means two
  locks and silent data loss, so this is enforced rather than advised.
- **Existing databases are converted to `journal_mode=WAL` on first open.**
  WAL is a property of the database *file*, not the connection — once converted,
  the database stays WAL for every later connection and process, permanently.
  A WAL database is **three files**: `<db>`, `<db>-wal`, `<db>-shm`.
  - **Any operator backup that copies the database file must now include the
    `-wal` / `-shm` sidecars, or checkpoint first**
    (`PRAGMA wal_checkpoint(TRUNCATE)`). Copying only the main file can silently
    lose committed transactions still resident in the WAL.
  - `vinctor operator storage backup` is unaffected — it dumps through a
    connection rather than copying the file.
  - If WAL cannot be enabled (a network filesystem, say), the service writes a
    warning to stderr and continues on the filesystem's default journal mode.
    WAL is required for concurrency, not for correctness.

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

Not reconstructed here. See the GitHub Releases page and `git tag`:

| Version  | Date       |
| -------- | ---------- |
| `v0.4.0` | 2026-07-13 |
| `v0.3.0` | 2026-07-13 |
| `v0.2.1` | 2026-07-12 |
| `v0.2.0` | 2026-07-11 |
| `v0.1.0` | 2026-06-25 |
