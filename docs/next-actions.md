# Next Actions

## Current Focus

Service application boundary:

- Add `vinctor_service` inside this repository.
- Start with an application service function over already-loaded grants.
- Do not add service storage, HTTP APIs, auth headers, or runtime hooks yet.

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

## Next

- Decide the first service repository interface for grant lookup.

## Open Questions

- Should `unresolved` remain service-layer only, or become a future core outcome?

## Validation Status

Use the latest commit and final report for exact command results.
