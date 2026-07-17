# ADR 0013: Append-only policy versions and exact rollback

## Status

Accepted.

## Context

Reapplying an old declarative policy is not a rollback when the apply operation
is additive: bounds or rules introduced later remain active. A safe operator
rollback must remove that residual authority while preserving security controls
that are not part of the policy document.

## Decision

- Each successful SQLite policy apply records the resulting workspace state in
  `policy_versions` with a monotonically increasing workspace-local version.
- A snapshot contains issuance bounds, auto-approval rules, and explicit
  require-boundary overrides, including disabled/exempt values.
- `operator policy rollback --version N` restores those three policy domains
  exactly and appends a new `rollback` version referencing `N`.
- Subject-token and PoP mandates remain unchanged during rollback.
- `require_boundary_set` distinguishes an explicit false override from a zero
  value introduced by another setting in the shared settings row. Existing
  databases migrate rows as explicit to preserve prior behavior.

## Consequences

Rollback removes authority introduced after the selected version and keeps an
auditable history rather than rewriting it. The first slice is SQLite-backed;
the same repository contract and migration must be added to Postgres before
Postgres policy administration reaches parity.
