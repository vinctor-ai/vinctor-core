# Next Actions

## Current Focus

Phase 4 authorization core vertical slice:

- Boundary Registry
- boundary-aware enforce decisions
- boundary-aware audit event construction

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

## Next

- Decide whether service-layer persistence/API belongs in this repository as a
  later package or in a separate repository.
- Add policy evaluation only after the already-issued grant model is stable.
- Add stricter scope validation if the next slice needs malformed-scope errors.
- Add packaging/release automation before publishing.
- Decide whether boundary names should be unique within a workspace.
- Decide whether disabled boundaries should support reactivation.

## Open Questions

- Should `unresolved` remain service-layer only, or become a future core outcome?
- What exact service package boundary should wrap this core later?

## Validation Status

Use the latest commit and final report for exact command results.
