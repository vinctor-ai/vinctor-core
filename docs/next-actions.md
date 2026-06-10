# Next Actions

## Current Focus

V1 service contract boundary:

- Keep `vinctor_service` as in-process application helpers.
- Preserve v1 enforce semantics before any HTTP or durable storage package.
- Do not add HTTP APIs, auth headers, DB persistence, hosted behavior, or
  runtime hooks yet.

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

## Next

- Decide whether a future repository interface should expose grant lookup by
  `grant_ref` directly or pass already-loaded grants into the v1 adapter.

## Open Questions

- Should `unresolved` remain service-layer only, or become a future core outcome?

## Validation Status

Use the latest commit and final report for exact command results.
