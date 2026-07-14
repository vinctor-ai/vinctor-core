# ADR 0014: Workspace-scoped read-only auditor key

## Status

Accepted.

## Context

Enterprise deployments need separation between operators that change policy or
issue authority and auditors that inspect the resulting trail. Reusing the
workspace admin key for audit export grants unnecessary mutation authority.
Authentication failures are intentionally unattributed when a bad credential
cannot be resolved, so exposing them to any workspace auditor could leak
cross-tenant activity.

## Decision

- Add a workspace-scoped `auditor` local key type with the `auk_` prefix.
- `X-Auditor-Key` is accepted only by the two audit read routes.
- Auditor keys are not resolved as workspace/operator identities, so every
  existing administrative route rejects them.
- Audit reads retain mandatory workspace filtering. Unscoped `auth_failed`
  events are not visible to workspace auditors.
- Creating and rotating auditor keys remains a host/operator action through
  `operator keys rotate auditor`.

## Consequences

Operators can hand a SIEM or human auditor a least-privilege credential without
sharing mutation authority. A future SSO integration can map an `auditor` role
to the same read contract. Fleet-wide visibility for unscoped authentication
failures uses the separate, narrow service-operator role defined in ADR 0015.
