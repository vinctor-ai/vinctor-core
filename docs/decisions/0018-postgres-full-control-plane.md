# ADR 0018: Complete the Postgres control-plane backend

## Status

Accepted.

## Context

The first Postgres slices persisted enforcement decisions, audit events,
boundaries, settings, and policies, but the HTTP service still depended on
SQLite for local identities, grant requests, subject tokens, and PoP replay
state. Starting a Postgres HTTP service would therefore have exposed only a
partial and misleading control plane.

## Decision

- Implement the remaining repository contracts in Postgres without changing
  deterministic core policy logic.
- Store only local-key hashes; keep raw-key creation and one-time display in a
  trusted administrative process.
- Keep subject-token PoP secrets available only to verification lookup, not
  operator get/list results.
- Serialize PoP nonce admission with a Postgres transaction advisory lock so a
  duplicate cannot be accepted by separate service instances.
- Serialize complete transactions on the built-in threaded server's per-process
  psycopg connection. Separate processes use separate connections.
- Allow `vinctor service serve` to select Postgres through the existing runtime
  configuration and use `SELECT 1` for traffic readiness.
- Keep SQLite as the default backend.

## Consequences

Multiple service processes can share grants, identities, approval workflow,
tokens, replay state, policy, and audit history through one Postgres database.
This removes the application storage blocker for horizontal instances. It does
not provide database HA, TLS, load balancing, backup scheduling, secret
management, or a hosted production service; operators must supply those pieces.
