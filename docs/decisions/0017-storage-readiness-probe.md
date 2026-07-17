# ADR 0017: Separate process liveness from storage readiness

## Status

Accepted

## Context

`GET /healthz` proves that the HTTP process can respond, but it cannot tell a
load balancer whether the service's durable store is usable. Returning healthy
during a database outage keeps a broken instance in rotation; turning the
liveness check into a database probe can instead cause unnecessary restart
loops.

## Decision

- Keep `/healthz` as a process liveness endpoint.
- Add unauthenticated `GET /readyz` as a traffic-readiness endpoint.
- Make readiness depend on an injected storage probe. SQLite service runtimes
  execute `SELECT 1`; the existing Postgres decision-storage handle exposes the
  same probe contract.
- Return `200` and `status: ready` on success. Return `503` and
  `status: unavailable` when the probe returns false or raises.
- Do not include database paths, DSNs, exception strings, or backend details in
  either response.
- Use `/readyz` for Compose and preview-container health checks.

## Consequences

An orchestrator can remove an instance from traffic during a durable-store
outage without treating the process as dead. This is a prerequisite for safe
multi-instance operation, not by itself a claim that a deployment has database
HA, load balancing, backups, or production-ready secret management.
