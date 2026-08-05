# ADR 0015: Service-operator view for unattributed authentication failures

## Status

Accepted.

## Context

Invalid credentials cannot be resolved to a workspace. Hiding their audit
events leaves operators blind to probing, while returning them to every
workspace auditor leaks cross-tenant security activity.

## Decision

- Add a global `service_operator` local key with the `sok_` prefix.
- Give it exactly one HTTP capability:
  `GET /v1/service/audit/auth-failures`.
- The view returns only `event_type=auth_failed` rows whose `workspace_id` is
  empty, with a bounded 1–200 result limit.
- The same credential gates `operator audit auth-failures` for local operations.
- A service-operator key does not resolve as a workspace or auditor identity.
  It cannot read workspace audit logs or invoke administrative routes.

## Consequences

Fleet operators gain visibility into credential probing without weakening
workspace isolation. SSO can later map a dedicated service-operator group to
this same capability; it must not implicitly grant the broader operator role.
