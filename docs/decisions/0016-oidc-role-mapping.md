# ADR 0016: OIDC bearer authentication and role mapping

## Status

Accepted

## Context

Local workspace, auditor, and service-operator keys are useful for bootstrap and
small installations. Enterprise deployments also need short-lived identities
issued by their existing identity provider without sharing mutation authority
with audit-only users.

## Decision

- Keep local keys enabled as a bootstrap and fallback authentication method.
- Optionally validate OIDC bearer JWTs against an explicitly configured issuer,
  audience, JWKS URL, and asymmetric algorithm allow-list.
- Map configured group names to three roles:
  - `operator` can use workspace administration and mutation routes.
  - `auditor` can read audit events for its workspace only.
  - `service_operator` can read the narrow, unscoped authentication-failure
    view only.
- Require a non-empty workspace claim for `operator` and `auditor`. The
  `service_operator` role is global and does not require one.
- Require workspace claims to match the issuer configuration's explicit
  workspace allow-list before granting any workspace-scoped role. An empty
  allow-list grants no workspace-scoped OIDC role.
- Prefer any explicitly supplied local-key header over a bearer token. Bearer
  tokens do not authenticate agent or PEP enforcement routes.
- Reject incomplete OIDC configuration at service startup. Reject tokens when
  signature, expiry, issuer, audience, subject, group, or workspace validation
  fails.

## Consequences

An enterprise can connect an existing IdP without changing Vinctor's policy or
audit ownership model. A compromised auditor identity cannot mutate policy, and
a service operator does not gain workspace audit access. The service depends on
JWKS availability for tokens whose signing key is not already cached; local
keys remain available for recovery.
