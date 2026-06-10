# Next Actions

## Current Focus

Repository boundary update:

- Document that this repository starts with `vinctor_core`.
- Allow future `vinctor_service` packages in this repository.
- Keep `vinctor_service` layered above `vinctor_core`.
- Do not start service wrapper work before scope validation unless explicitly
  approved.

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

## Next

- Add scope validation before starting an HTTP service wrapper.
- Define allowed action verb validation.
- Reject malformed grant scopes.
- Define resource wildcard rules.
- Add invalid grant scope reason codes.
- Add invalid requested action/resource handling.
- Cover validation behavior with tests.
- Add policy evaluation only after the already-issued grant model and scope
  validation are stable.
- Add packaging/release automation before publishing.
- Decide whether boundary names should be unique within a workspace.
- Decide whether disabled boundaries should support reactivation.

## Open Questions

- Should `unresolved` remain service-layer only, or become a future core outcome?
- Should future service code live under `vinctor_service` in this repository, or
  remain in a separate repository until persistence/API behavior is stable?

## Validation Status

Use the latest commit and final report for exact command results.
