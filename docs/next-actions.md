# Next Actions

> **Superseded — historical snapshot, last updated 2026-06-27.**
>
> This file is no longer maintained and does not describe the current state of
> the project. It predates the Postgres control plane, OIDC, the action
> taxonomy, and the 2026-07 hardening work, so it reads as a live tracker while
> being materially out of date.
>
> - Durable design decisions: [`docs/decisions/`](decisions/README.md)
> - Shipped and unreleased changes: [`CHANGELOG.md`](../CHANGELOG.md)
>
> Kept for historical context only — do not plan work from it.

## Current Focus

V1 service contract boundary:

- Keep `vinctor_service` as in-process application helpers.
- Preserve v1 enforce semantics while adding service-layer storage and HTTP
  wrappers above the contract boundary.
- Keep local/self-hostable HTTP helpers thin and explicit. Do not add hosted
  behavior, production server claims, runtime hooks, or runtime adapter
  implementations.

## Proposed (design specs — pending founder review)

Two capabilities were spec'd 2026-07-01, motivated in part by a competitive look at
AgentPerms (an OSS MCP stdio-proxy). Each spec leads with *why* and defers code to a
follow-up ADR + plan.

- **Record → Infer: bootstrap grants from audit traces** —
  [spec](superpowers/specs/2026-07-01-record-infer-policy-from-audit.md). Why: the
  blank-page problem (hand-authoring least-privilege scopes) is the adoption killer;
  we already persist a post-enforcement `(action, resource)` trace in `audit_events`,
  so we can propose a minimal grant from observed behavior with no separate recorder.
  Propose-only, never auto-apply.
- **Non-bypassable enforcement for MCP tool calls** —
  [spec](superpowers/specs/2026-07-01-mcp-non-bypassable-enforcement.md). Why: our
  Phase-1 hook is cooperative/bypassable; the Phase-1.8 delegated-enforce mechanism
  (ADR 0007) already ships but has no instrumented resource. MCP is the ideal first
  resource-side PEP because its transport allows complete mediation. Code lives in an
  adapter (not core).

## Done

- Created the initial Python package scaffold.
- Added typed core models for grants, boundaries, decisions, and audit events.
- Added an in-memory boundary registry.
- Added scope matching for exact scopes and terminal resource wildcards.
- Added boundary-aware `evaluate_enforce`.
- Added deterministic audit event construction.
- Added behavior tests and an in-process E2E demo.
- Added GitHub Actions CI for tests, demo, Ruff, and whitespace checks.
- Added JSON-safe audit event serialization.
- Added workspace-safe boundary lookup and boundary disable helpers.
- Documented that service-layer packages may live in this repository later if
  they remain layered above the deterministic core.
- Added scope validation for allowed action verbs, requested resources, grant
  scope grammar, and terminal resource wildcards.
- Added core-only policy evaluation across explicit already-issued grant
  candidates.
- Added package build verification before publishing.
- Enforced workspace-local boundary name uniqueness.
- Added disabled boundary reactivation while preserving boundary identity.
- Added `vinctor_service.authorize_action` as a thin application service
  boundary over `vinctor_core.evaluate_policy`.
- Added `vinctor_service.enforce_v1_contract` to preserve v1 enforce
  pre-audit failures, audit-before-decision behavior, and service-style
  response mapping without adding HTTP or storage.
- Added a service-layer `GrantRepository` protocol and in-memory implementation
  so v1 enforce lookup behavior is explicit without adding durable storage.
- Added a service-layer `AuditWriter` protocol and in-memory implementation so
  v1 audit-before-decision behavior is explicit without adding durable storage.
- Added `InMemoryV1Service` to compose the in-memory grant repository, audit
  writer, boundary registry, and v1 enforce adapter for integration tests and
  local demos.
- Added SQLite-backed grant lookup and audit writing for the existing
  service-layer repository/writer abstractions.
- Added SQLite-backed boundary registry support for durable boundary lookup,
  active/disabled state, and boundary context in audit rows.
- Added `SQLiteV1Service` to compose SQLite grant lookup, audit writing,
  boundary registry, and v1 enforce behavior for local in-process use.
- Added small `SQLiteV1Service` helpers for audit lookup and boundary
  registration/disable/enable/list operations.
- Added a v1 HTTP contract adapter for `X-Agent-Key`, strict enforce request
  body validation, optional boundary header mapping, and response shaping.
- Added a stdlib local HTTP wrapper for `POST /v1/enforce` demos and
  integration tests that delegates to the v1 HTTP contract adapter.
- Added workspace-key-protected boundary registry HTTP contract adapters for
  `POST /v1/boundaries`, `GET /v1/boundaries`, and
  `GET /v1/boundaries/{boundary_id}`.
- Added boundary status HTTP contract adapters for
  `POST /v1/boundaries/{boundary_id}/disable` and
  `POST /v1/boundaries/{boundary_id}/enable`.
- Added a local service launch helper that bootstraps SQLite grant/boundary
  state, starts the stdlib local HTTP server, and prints copy-pasteable
  `VINCTOR_*` exports for local runtime-hook usage.
- Added durable SQLite local key records for `X-Workspace-Key` and
  `X-Agent-Key`, storing only key hashes plus metadata and resolving identities
  through the service layer.
- Tightened local bootstrap exports to quoted shell assignments and added a
  bootstrap demo covering generated keys, explicit key reuse, enforce, and
  boundary-aware audit.
- Ran an agent-based local bootstrap dogfooding pass, recorded findings, and
  improved operator UX with a top-level quickstart, restart guidance, CLI help,
  and visible grant expiry.
- Dogfooded the explicit local key flow with the sibling
  `vinctor-claude-code-hook` repository as a real caller outside this repo:
  first launch printed raw keys, hook CLI enforcement worked, restart with
  explicit `--workspace-key` and `--agent-key` worked, and SQLite audit rows
  recorded the expected permit/deny/permit sequence.
- Added the first grant issuance lifecycle: workspace-key-protected
  service-issued scoped grants, agent issuable scope bounds, grant lookup,
  grant revocation, TTL enforcement through the existing enforce path, and
  `grant_issued` / `grant_revoked` audit events.
- Recorded grant lifecycle JIT semantics in
  `docs/decisions/0003-grant-lifecycle-jit-semantics.md`: JIT means issuance
  timing plus scoped, time-bounded, revocable authority, not a single-use token.
- Updated the local launcher so new local grants are issued through the service
  lifecycle path instead of treating direct SQLite seeding as the primary flow.
- Added a grant lifecycle demo covering issue, enforce, revoke, and denied
  enforce after revocation.
- Added the first grant request lifecycle: agents can create pending scoped
  grant requests with `X-Agent-Key`, workspace/admin authority can list, look
  up, approve, or reject them with `X-Workspace-Key`, and approval reuses the
  existing service-issued grant path.
- Added grant request audit events for `grant_requested`,
  `grant_request_approved`, and `grant_request_rejected`.
- Added a grant request lifecycle demo covering request, approval, issued
  grant consumption, and audit event order.
- Recorded approval authority rules in
  `docs/decisions/0004-approval-authority-and-auto-approval-rules.md`: execution
  agents may request authority but must not define or invoke the rules that
  approve their own requests.
- Added admin-defined auto-approval rule models, in-memory and SQLite rule
  repositories, and a dry-run evaluator that reports whether a pending grant
  request would be approved without mutating the request or issuing a grant.
- Added an auto-approval dry-run demo covering rule creation, request creation,
  evaluation, and the fact that the request remains pending.
- Added workspace-key-protected HTTP/admin contracts for creating, listing, and
  disabling auto-approval rules: `POST /v1/auto-approval-rules`,
  `GET /v1/auto-approval-rules`, and
  `POST /v1/auto-approval-rules/{rule_id}/disable`.
- Added an auto-approval HTTP/admin demo covering workspace-managed rule
  creation/listing/disable and rejecting agent-key rule management.
- Added the auto-approve service path: workspace/admin-triggered
  `POST /v1/grant-requests/{request_id}/auto-approve` evaluates pending grant
  requests against active admin-defined rules and, on match, reuses the existing
  grant request approval plus service-issued grant lifecycle.
- Added `grant_request_auto_approved` audit events and a service path demo
  covering request creation, rule match, grant issuance, enforce consumption,
  and audit order.
- Recorded grant request routing and approval mode semantics in
  `docs/decisions/0005-grant-request-routing-and-approval-modes.md`:
  auto-approval is opt-in for low-risk repeatable requests, non-matches remain
  pending, and higher-risk requests should stay available for human/operator
  review or workspace/admin rejection.
- Added `python -m vinctor_service.local_admin` as a local operator helper for
  grant request queue visibility, manual approve/reject, auto-approve attempts,
  auto-approval rule management, local agent issuable scope bounds, enforce
  checks, and recent audit viewing.
- Added a local operator flow demo that drives the helper through rule creation,
  grant request creation, queue inspection, auto-approval, enforce, and audit
  viewing against a temporary local service.
- Updated `vinctor-claude-code-hook` so it forwards optional
  `VINCTOR_BOUNDARY_ID` as `X-Vinctor-Boundary-Id`, allowing hook-originated
  local audit rows to include boundary context.
- Added operator-facing approval mode examples for CI, docs edits, staging and
  production deploys, secret reads, destructive actions, and disabled rules in
  `docs/operator-policy-authoring/approval-mode-examples.md`.
- Updated `vinctor-codex-hook` so it forwards optional
  `VINCTOR_BOUNDARY_ID` as `X-Vinctor-Boundary-Id`, allowing Codex-originated
  local audit rows to include boundary context.
- Updated `vinctor-hermes-plugin` so it forwards optional
  `VINCTOR_BOUNDARY_ID` as `X-Vinctor-Boundary-Id`, allowing Hermes-originated
  local audit rows to include boundary context.
- Recorded the local prototype CLI design in `docs/cli-design.md`, including
  role-separated `vinctor local`, `vinctor agent`, `vinctor operator`, and
  `vinctor demo` command surfaces.
- Added the `vinctor` console entrypoint as a thin local prototype CLI over the
  existing service contracts and SQLite helpers.
- Added non-authoritative grant request routing hints to creation responses:
  `auto_approval_available` or `manual_review_required`.
- Added a manual-review-required demo showing a non-matching auto-approval
  attempt that leaves a request pending until operator approval.
- Added a local hook integration runbook that documents service startup,
  `VINCTOR_*` runtime exports, and boundary-aware audit inspection without
  editing sibling hook repositories.
- Added a git repo boundary demo scenario showing that a grant scoped to
  `write:repo/vinctor-core/*` does not authorize writes in sibling repos.
- Added `vinctor operator audit list` filters for event type, grant ref,
  boundary id, and request id.
- Added `vinctor demo check` as a single local smoke check covering rule
  creation, request creation, auto-approval, enforce, and audit count.
- Added local `policy.yaml` import/export for agent issuable scope bounds and
  auto-approval rules through `vinctor operator policy apply/export`.
- Added an agent-safe request status path: agents may `GET` only their own
  `grant_request` records and use `vinctor agent requests status`.
- Added queue-facing routing and queue reason fields to workspace grant request
  views so pending requests explain why they are pending.
- Added local SQLite schema migration metadata and `vinctor operator storage
  info` for demo/storage sanity checks.
- Recorded local bootstrap key-reuse boundaries in
  `docs/decisions/0006-local-bootstrap-ux-and-key-reuse.md`.
- Added `docs/api-contract.md` for the current local v1 HTTP API contract and
  reason codes.
- Added `docs/demo-service-runbook.md` and `docs/examples/local-demo-policy.yaml`
  for repeatable local demo service setup.
- Added `tools/mock_vinctor_service.py` as a stdlib-only deterministic
  `/v1/enforce` fixture for Claude/Codex/Hermes hook/plugin smoke tests, plus
  `docs/testing/mock-vinctor-service.md` and a demo.
- Added `vinctor demo service` as a one-command service-style demo covering
  policy apply, auto approval, manual approval, enforce, repo-boundary deny, and
  audit verification.
- Added explicit `vinctor local env --write-file` support for test/dev env
  files, with `.vinctor.env` ignored by git.
- Added optional grant request metadata fields for task, session, boundary,
  runtime, repo, and worktree context.
- Added `vinctor operator requests inbox` and `vinctor operator requests
  timeline` for pending request review and audit timeline viewing.
- Added local demo policy templates under `docs/examples/policies/`.
- Added `docs/openapi/v1.yaml` and `make demo` as a simple demo entrypoint.
- Added a self-hostable service foundation with `vinctor service serve`, a
  small runtime config model, `/healthz`, a separated serve-only runtime path,
  minimal Docker/Compose files, `docs/deployment/self-hosting.md`, and
  `demo/self_hostable_service_demo.py`.
- Corrected lifecycle audit semantics so rejected grant requests and revoked
  grants no longer appear as `permit` decisions in audit records.
- Centralized scope containment checks in `vinctor_core.scope.scope_subsumes` so
  grant issuance bounds and auto-approval rules share the same deterministic
  predicate.
- Added workspace-key-gated `vinctor operator audit export --format jsonl` for
  full local audit export without adding model-facing raw inputs.
- Added the first operational interface slice on top of the self-hostable
  foundation: `vinctor operator storage backup --output` (consistent SQLite
  snapshot, `--force` to overwrite), `vinctor operator storage reset --yes`
  (wipe and recreate empty schema, no implicit backup), and
  `vinctor operator service info` (safe mode/host/port/db-path/schema-version
  metadata that never creates a database or prints raw keys/hashes), with a
  `storage_ops` helper module, focused tests, and an operator storage ops demo.
- Completed the operational interface command surface: `vinctor operator storage
  restore --input --yes` (validates the snapshot before replacing the live DB),
  `vinctor operator storage migrate` (explicit idempotent schema apply +
  version report), and `vinctor operator keys list` / `revoke <key_id>` /
  `rotate workspace` / `rotate agent --agent-id` (masked key metadata, revoke by
  id, rotation that mints a replacement and revokes the prior active key while
  printing the new raw key only once). Added a `key_ops` helper module, extended
  `storage_ops`, focused tests, and a full lifecycle demo.
- Added `docs/deployment/operational-runbooks.md` with starting-point operator
  runbooks for network/binding, TLS/reverse proxy, firewall, systemd
  supervision, logs/observability (honest about suppressed per-request logging
  and audit records as the operational signal), and SQLite/Docker-volume
  backup/restore. Linked from `self-hosting.md`; no production-readiness claims.
- Added ADR 0008 operator-only auditing of pre-grant-evaluation rejections
  (agent↔grant mismatch, rate-limited/aggregated auth failures, out-of-bounds
  issuance) carrying a coarse `reason_code`, with caller responses byte-for-byte
  unchanged (`#51`/`#53`/`#54`).
- Made `vinctor operator policy apply` atomic: the whole document is validated
  before any write, so a malformed later entry no longer leaves earlier bounds
  committed (`#55`).
- Added `docs/cli-reference.md` (a per-config-value CLI reference, source- and
  `--help`-verified) and ran a cross-repo docs-standards sweep.
- Implemented ADR 0007 Model 2 identity proof: Vinctor-issued, grant-bound,
  audience-scoped, short-lived subject tokens (`vat_`) via `POST /v1/tokens` +
  `vinctor agent token mint`, plus an additive optional `X-Subject-Token` on
  `/v1/enforce/delegated` that proves the subject (audited `identity_proven` +
  `token_id`), fails closed on any token failure, and never leaks the raw token;
  PEP resolver wired into both `serve` and `local start`. Schema v3 (`#58`).
- Implemented ADR 0009-B per-agent `require_boundary`: an opt-in
  `agent_enforcement_settings` flag (schema v4) that fails a hardened agent's
  enforce closed (`boundary_required`) when the boundary is truly absent — making
  the `disable` kill-switch un-evadable — while leaving the default-off path
  unchanged; `vinctor operator require-boundary enable|disable|show` CLI (`#60`).
- Ran the runtime-authorization dogfooding arc (rounds 1–8: authz boundary,
  Codex measurement, tenant/delegation, MCP inspection, approval flow, the
  4-area parallel batch, the ADR 0007 proven path, and ADR 0009-B
  require_boundary), recorded in `docs/dogfooding/2026-06-21-dogfooding-summary.md`.
  Findings dispositioned: D2→ADR 0008, D3→`#52`, policy non-atomic→`#55`,
  boundary opt-in→ADR 0009-B.
- 2026-06 build program (A–E), all merged to main and adversarially reviewed:
  - **A** install ergonomics — clean `pipx`/`pip install` → `vinctor` path +
    project URLs (`#63`).
  - **B** `require_boundary` workspace-default + per-agent override + policy-file
    surface (`#64`).
  - **C1** subject-token revocation (`operator tokens revoke/list`) +
    `require_subject_token` mandate (`#65`).
  - **C2** per-action subject-token binding (`#66`).
  - **C3** stdlib HMAC proof-of-possession for subject tokens (`#67`).
  - **D** opt-in structured access log + `/metrics` Prometheus endpoint, both
    default off (`#68`).
  - **E** MCP Phase 2 safe core — opt-in operator `approve`/`reject` write tools
    (`#69`).
  Test suite 351 → 484; dependencies still stdlib + PyYAML; SQLite schema v7.
- 2026-06 backlog follow-on program (F–L), all merged to main and adversarially
  reviewed:
  - **F** MCP `vinctor_revoke_grant` (`#71`); **G** tagged-release CI — GHCR image
    + GitHub Release artifacts on the automatic token, opt-in PyPI (`#72`).
  - **H** MCP `vinctor_issue_grant` — completes the Phase 2 write set
    (approve/reject/revoke/issue) (`#73`).
  - **I** opt-in `require_pop` operator mandate (schema v8, the third enforcement
    flag) (`#74`).
  - **J** durable SQLite-backed PoP replay store (schema v9) — restart-durable +
    cross-process-correct anti-replay (`#75`).
  - **K** CLI cosmetics — `enforce -o json` single object on deny + `policy export`
    round-trip symmetry (`#76`).
  - **L** MCP Phase 3 composite read-only reports (`vinctor_grant_report` /
    `vinctor_boundary_report`) — zero new service surface (`#77`).
  Test suite 484 → 518; dependencies still stdlib + PyYAML; SQLite schema v7 → v9.
- 2026-06-25 **v0.1.0 release prep**, all merged to main:
  - `operator grants revoke` CLI (`#81`); golden-path demo `vinctor demo block` +
    hero GIF (`#82`).
  - **Security hardening** from the multi-agent audit (`#83`): pre-auth request-body
    cap + handler timeout + parse-pop-skew-once (the release-gate HIGH);
    grant-existence oracle closed (unknown vs foreign grant now an identical
    `403 forbidden`, enforce 404→403, mismatch audit attributed to the caller's own
    workspace); naive `expires_at` coerced to UTC; container runs non-root;
    GitHub Action `uses:` pinned to commit SHAs; bundled compose binds `127.0.0.1`.
  - **CLI UX quick-wins** (`#84`): global/output flags accepted after the subcommand,
    `vinctor --version`, malformed-credential → clean error, help text across the tree.
  Test suite 518 → 551; deps still stdlib + PyYAML; version `0.1.0`.

### Deferred to v0.1.1 (from the security audit + CLI review)
- **Security — SHIPPED 2026-06-26 (PR #86):** audit list/export SQL pushdown
  (full-table scan → workspace-scoped WHERE/ORDER/LIMIT + index, schema v10); PoP
  replay per-token partition (`max_per_token` — one token can no longer lock out
  others); SBOM/provenance on the release image + a HEALTHCHECK.
- **Security — SHIPPED 2026-06-26:** a real per-source request rate limiter
  (opt-in `VINCTOR_RATE_LIMIT_PER_MINUTE`, fixed-window per-source-IP, pre-auth
  `429`, default off, fail-open; see `docs/cli-reference.md`).
- **Security (still deferred):** pin the Docker base image by digest (needs a
  docker-equipped CI run); pop_secret encryption at rest.
- **CLI bigger calls (need a decision, breaking):** unify the HTTP-vs-direct-DB
  operator transport split; collapse the three `require-*` mandates into one
  `operator mandate` noun; rename `operator bounds` to a ceiling-signalling name;
  reconsider the agent/operator persona split. (All need a deprecation window.)

## Next

- The operator command surface for the self-hostable foundation is complete:
  storage backup/reset/restore/migrate, safe service info, and keys
  list/revoke/rotate. Remaining operational work is deployment-ops docs, not new
  commands.
- Deployment-ops runbooks (TLS/reverse proxy, firewall, systemd, logs, SQLite/
  volume backup) are written in `docs/deployment/operational-runbooks.md`.
  Opt-in structured access logging + a `/metrics` Prometheus endpoint shipped
  (off by default, `#68`). Tagged-release CI shipped (`.github/workflows/
  release.yml`): a `v*` tag builds the sdist/wheel + GitHub Release artifacts and
  pushes the GHCR image via the automatic `GITHUB_TOKEN` (no extra creds); PyPI
  publish is opt-in (`PUBLISH_PYPI` repo variable + Trusted Publishing or a
  `PYPI_API_TOKEN` secret). Remaining: the user cuts the first real tag when
  ready, and (if desired) enables PyPI publishing.
- Keep local config-file auto-reuse and OS keychain integration deferred until
  the local bootstrap UX is stable enough for a separate ADR-backed slice.
- Keep production deployment hardening deferred. The current self-hosting
  support is single-node prototype infrastructure, not HA or managed auth.
- Consider HTTP-level policy import/export once a hosted or long-running service
  deployment contract exists. Current policy file apply/export is local
  SQLite-backed.
- SQLite schema is at version 4 (adds subject tokens and agent enforcement
  settings); backup, reset, restore, and `vinctor operator storage migrate` have
  all shipped. Further migration tooling is only needed if a non-additive
  migration arises (current additions are `CREATE TABLE IF NOT EXISTS` + a version
  row).
- Add richer reviewer identity and operator inbox assignment only after a
  concrete human/operator workflow exists.
- Add stronger local secret storage such as OS keychain integration only after
  a separate design slice. Current env-file support is explicit test/dev UX.

### Hardening follow-ups (deferred from the 2026-06 ADR 0007 / 0009-B slices)

**Shipped 2026-06** — ADR 0007 fully hardened (revocation + `require_subject_token`
`#65`, per-action binding `#66`, stdlib HMAC PoP `#67`) and ADR 0009-B follow-ups
(workspace-default + per-agent override + policy-file surface `#64`).

**Shipped 2026-06** — durable/shared PoP replay cache: `SQLiteReplayStore`
(schema v9, table `pop_replay_nonces`) drops in behind the existing
`check_and_record` contract, so anti-replay is now restart-durable and
cross-process-correct (the `(token_id, nonce)` PRIMARY KEY enforces dedup at the
db file; the in-memory `PopReplayCache` stays for `in_memory.py` / tests). This
closes the per-process replay residual. Multi-process throughput tuning
(`PRAGMA journal_mode=WAL` + `busy_timeout`) remains an optional further
follow-up; the PK-enforced atomic dedup is already cross-process-correct without
it.

**Shipped 2026-06** — opt-in `require_pop` operator mandate (`#74`, schema v8, the
third enforcement flag): when set for a (workspace, agent), a delegated enforce
whose subject token is not PoP-bound (`pop_secret is None`) fails closed with the
generic 403 + audit `reason_code=pop_required`. Shipped single-purpose (presented
non-PoP tokens only, composing with `require_subject_token`); **revised 2026-07-12
(`#116`)**: `require_pop` now also denies the no-token case — it implies a subject
token must be presented, subsuming `require_subject_token` rather than composing
with it. Tenant-isolated on `trusted_ws`; `operator require-pop
enable/disable/show`.

Remaining (deferred — each needs a founder decision / posture change, NOT
autonomously taken):
- **Asymmetric DPoP / mTLS PoP** (Vinctor never holds the secret) — needs a crypto
  dependency, which reverses the deliberate stdlib-only / symmetric-HMAC posture.
  Needs an explicit founder decision before adoption.
- **True single-use tokens** — deferred as retry-fragile; per-action binding +
  revocation + short TTL + HMAC-PoP already bound the replay window. Revisit only
  if a concrete single-use requirement appears.

### Measurement / adoption (not autonomously reproducible)

- Hermes runtime boundary measurement (feasibility uncertain).
- Claude Code real-use dogfood (interactive `claude -p` driving of the
  hook → enforce loop).
- Codex `emitted?` stays unmeasured: headless `codex exec` does not load plugin
  hooks on 0.137.0; revisit only if the TUI becomes driveable or a newer build
  changes this.

### Low-priority cosmetics

**Both shipped 2026-06 (`#76`):**
- `vinctor agent enforce -o json` now emits a single JSON object on deny (the
  decision on stdout; the stderr error line is suppressed in JSON mode for the
  deny case only, exit code unchanged).
- `vinctor operator policy export` now emits the `max_ttl` key the input used (as
  `"<N>s"`) for a symmetric, idempotent round-trip (apply still accepts the legacy
  `max_ttl_seconds` key).

### MCP Phase 2 - Approval / Grant Administration

Status: **Write set complete 2026-06 (`#69`)** — opt-in (`VINCTOR_MCP_WRITE`, default
off) `vinctor_approve_grant_request` / `vinctor_reject_grant_request` proxying the
workspace-key operator endpoints (the service audits and structurally prevents
execution-agent self-approval). `vinctor_revoke_grant` shipped 2026-06 (proxies the
existing `POST /v1/grants/{grant_ref}/revoke` endpoint, same opt-in + audit
discipline). `vinctor_issue_grant` shipped 2026-06 (proxies the existing
`POST /v1/grants` endpoint; the service enforces the workspace's issuable-scope
bounds and max TTL and audits the issuance, same opt-in discipline — the MCP mints
nothing). **Phase 2 write set complete.**

Goal: Extend the MCP server from read-only inspection into a privileged approval
and grant administration interface.

Requirements:

- Maintain the current architecture:
  - MCP remains a control-plane interface.
  - `vinctor-service` remains the authorization authority.
  - `enforce()` remains the runtime enforcement boundary.
- Do not replace `enforce()`.
- Do not execute protected actions.
- Do not mint grants locally.
- Do not store authorization state in MCP.
- Do not allow self-approval by execution agents.

Proposed MCP tools:

- Approvals:
  - `vinctor.approvals.list_pending`
  - `vinctor.approvals.get`
  - `vinctor.approvals.approve`
  - `vinctor.approvals.reject`
- Grant administration:
  - `vinctor.grants.list_active`
  - `vinctor.grants.revoke`
  - `vinctor.grants.issue` (service-authorized only)

Security requirements:

- Separate admin credentials from runtime credentials.
- Approval actor must be auditable.
- All approval actions generate audit events.
- Service-issued grants remain the only valid grants.
- Execution agents must not be able to approve their own requests.
- Approval actions must be scoped and revocable.

Deliverable: Operator-facing approval workflow integrated with
`vinctor-service` while preserving the current runtime authorization
architecture.

### MCP Phase 3 - Operational UX and Authorization Visibility

Status: **Composite read-only reports shipped (2026-06)** — the zero-new-service-
surface slice. Two composite read tools (`vinctor_grant_report`,
`vinctor_boundary_report`) synthesize existing reads (the `vinctor_explain_denial`
pattern): `grant_report` returns a grant plus its audit timeline partitioned into
lifecycle (issued/revoked) and usage (enforcement decisions) events;
`boundary_report` returns a boundary plus a permit/deny summary and recent audit
events. Both are registered unconditionally as read tools, add only fixed keys +
server-computed integer counts, and inherit the read tools' allowlist shaping.

Deferred (each needs NEW service surface, out of this slice):

- durable grant lifecycle timestamps (`issued_at` / `revoked_at`)
- an authoritative boundary-to-grant join
- server-side audit aggregation and time-range filtering
- subject-token and workspace-settings read endpoints

Goal: Improve operator understanding of runtime authorization state without
expanding MCP into an execution platform.

Potential additions:

- Boundary visibility:
  - `vinctor.boundaries.explain`
  - boundary-to-policy mapping explanation
  - boundary-to-grant relationship inspection
- Authorization visibility:
  - denial reason explanation
  - grant usage inspection
  - grant lifecycle inspection
  - active authorization state summaries
- Audit navigation:
  - richer audit filtering
  - boundary-centric audit views
  - grant-centric audit views
- Future memory/context integration, if introduced later:
  - memory authorization visibility
  - context authorization visibility
  - memory boundary explanation

Important:

- MCP should remain an inspection and administration interface.
- Do not convert MCP into a policy engine.
- Do not convert MCP into a runtime gateway.
- Do not convert MCP into a generic agent platform.
- Do not move authorization logic out of `vinctor-service`.

Deliverable: Improved operational visibility, debugging, and explainability for
Vinctor authorization state while preserving existing enforcement boundaries.

### Onboarding / first-run friction (2026-06-25 OSS 5-min experience audit)

A fresh-clone walkthrough of the public install→demo path (venv `pip install .`
on vinctor-core + `npm install && npm run build` on vinctor-claude-code-hook).
Everything builds, the demos pass, and the claims hold — the gap is that the
"dangerous action blocked" aha is buried. Captured as the funnel-critical
pre-promotion backlog.

- **[core+hook] No single "watch a dangerous action get blocked" golden-path
  demo (epic, funnel-critical).** Seeing a real `deny: action_denied` today
  requires two repos, two package managers (pip + npm), manual `VINCTOR_*`
  export copying, and a `settings.json` edit — there is no one-command scene to
  record as a GIF / README hero. Direction: a single golden path (a
  `vinctor demo block`-style command or quickstart script) that starts the local
  service, issues a grant, then shows a dangerous call DENIED with a
  human-readable reason and an allowed call passing. Packaging of existing parts,
  not new authz behavior.
- **[hook] Offline deny reason reads as a setup error — RESOLVED 2026-06-26**
  (claude-code-hook PR #21 + codex-hook PR #5, parity). The `missing_auth_env` /
  `service_unavailable` deny templates now read as a deliberate fail-closed security
  decision ("…not a setup error. Configure/restore the service to get a real
  allow/deny decision."). Kept STATIC: the "surface the classified action/resource
  in the reason" direction was REJECTED — it would violate the hook's deliberate
  no-disclosure invariants (reason-templates fixed set, no-tool-input-disclosure
  across the missing_auth_env matrix row, no-`${}` structural guard; the resource can
  carry a host/path fragment). Seeing the concrete `action_denied` is the golden-path
  demo's job (drive it through a live local service).
- **[core] `pipx` install path fallback — DONE 2026-06-26 (PR #87).** README now
  says "no pipx on this machine? install into a virtualenv instead" inline.
- **[core] `vinctor demo service` abstract output — DONE 2026-06-26 (PR #87).**
  Replaced with human-readable ALLOW/DENY narration (`_demo_service_text` +
  `_demo_verdict_label`); JSON output unchanged.
- **[hook] `explain` stdin (`-`) — ALREADY WORKS (verified 2026-06-26).** Both
  `… | explain` and `… | explain -` read the event from stdin and classify it
  (stdin support was added during the cold-e2e work). No change needed.
- **[core] Path-traversal authz bypass — FIXED 2026-06-27 (HIGH).** A wildcard
  grant `write:repo/feature/*` previously PERMITTED
  `write repo/feature/../protected/secrets` (resolving to a forbidden path)
  because `_is_valid_resource` accepted `..` as a literal segment. Fix: resource
  scopes now reject any whole `.` or `..` path segment (fail-closed) at both
  grant-scope validation and requested-resource validation. Dotted names
  (`orders.api`, `v1.2`) stay valid. stdlib only, no schema change.

## Open Questions

- Should `unresolved` remain service-layer only, or become a future core outcome?

## Validation Status

Use the latest commit and final report for exact command results.
