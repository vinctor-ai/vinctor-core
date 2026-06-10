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

## Next

- Decide whether to add a small local service launch helper or keep local HTTP
  server construction explicitly in demos/tests.

## Open Questions

- Should `unresolved` remain service-layer only, or become a future core outcome?

## Validation Status

Use the latest commit and final report for exact command results.
