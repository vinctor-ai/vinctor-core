# Next Actions

## Current Focus

V1 service contract boundary:

- Keep `vinctor_service` as in-process application helpers.
- Preserve v1 enforce semantics while adding service-layer storage and HTTP
  wrappers above the contract boundary.
- Keep local HTTP helpers thin and explicit. Do not add hosted behavior,
  production server claims, runtime hooks, or runtime adapter implementations.

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

## Next

- Keep local config-file auto-reuse and OS keychain integration deferred until
  the local bootstrap UX is stable enough for a separate ADR-backed slice.
- Consider HTTP-level policy import/export once a hosted or long-running service
  deployment contract exists. Current policy file apply/export is local
  SQLite-backed.
- Add explicit SQLite backup/reset/upgrade commands after schema migration needs
  exceed the current version marker.
- Add richer approval queue fields only when new request metadata exists, such
  as task id, session id, boundary id at request time, or human reviewer id.

## Open Questions

- Should `unresolved` remain service-layer only, or become a future core outcome?

## Validation Status

Use the latest commit and final report for exact command results.
