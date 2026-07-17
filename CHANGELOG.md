# Changelog

Notable changes to `vinctor-core`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file was adopted on 2026-07-17. Releases made before that date are listed
by version and date only and are not reconstructed change-by-change — see the
GitHub Releases page and the git tags for those. The `Unreleased` section is
authoritative going forward.

## [Unreleased]

Everything in this section is merged to `main` and **has not been published**.

`pyproject.toml` already reads `0.4.0`, but **this repository has no `v0.4.0`
tag** — its last tag is `v0.3.0` (2026-07-13). The published 0.4.0 artifact on
PyPI and GHCR was built and released from the public mirror's 2026-07-13
snapshot, which predates every change listed below (that snapshot carries ADRs
0001–0011 only; ADRs 0012–0018 all landed after `v0.3.0`). The next release
should therefore be **0.5.0**, not a 0.4.x patch.

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

- **`SerializedSQLiteConnection`** (#149) — a single ownership root for SQLite
  connections: `connect_sqlite` is now the only raw opener and
  `require_serialized` rejects a raw `sqlite3.Connection`. **This changes the
  embedder contract** — code that passed its own `sqlite3.connect(...)` to a
  service or repository must switch to `connect_sqlite`.
- Gradual-rollout guide — #146.

### Fixed

- Postgres audit-verify parity — #144.
- Postgres control-plane close (#141), proposal evidence expectations (#142),
  and a service-runtime conflict marker (#140).

### Security

- **TIER-3 security hardening** (#148) — 16 fixes closing roughly 20 findings
  from two independent reviews, over 6 adversarial review rounds: no-disclosure
  sanitization of agent-facing denials, PoP replay fail-closed, delegated
  workspace binding, audit seq-ordering and cross-check, atomic policy-apply and
  grant-decision CAS.

## Released

Not reconstructed here. See the GitHub Releases page and `git tag`:

| Version  | Date       |
| -------- | ---------- |
| `v0.3.0` | 2026-07-13 |
| `v0.2.1` | 2026-07-12 |
| `v0.2.0` | 2026-07-11 |
| `v0.1.0` | 2026-06-25 |
