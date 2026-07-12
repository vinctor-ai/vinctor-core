# Service package in this repository

- status: accepted
- date: 2026-06-10

## Context

`vinctor-core` started as a deterministic authorization core. The repository
direction now allows a layered service package to live here as long as the core
remains DB/HTTP/runtime-agnostic.

## Decision

Keep `vinctor_service` in this repository alongside `vinctor_core`.

Start `vinctor_service` with application service functions, not HTTP routes,
durable storage, auth headers, hosted service behavior, or runtime adapter
hooks.

The initial service boundary is `authorize_action`, which maps a service-shaped
authorization request and already-loaded grant candidates onto
`vinctor_core.evaluate_policy`.

## Consequences

- `vinctor_service` may import `vinctor_core`.
- `vinctor_core` must not import `vinctor_service`.
- The first service package does not claim production readiness.
- Future HTTP, auth, persistence, and audit storage work should build above
  this application boundary instead of bypassing it.
