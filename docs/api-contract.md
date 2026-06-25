# Local V1 API Contract

This document records the current local prototype HTTP contract. It does not
claim hosted service behavior or production readiness.

Machine-readable schema: `docs/openapi/v1.yaml`.

## Health

`GET /healthz`

Auth: none

Response:

```json
{
  "status": "ok",
  "service": "vinctor-service",
  "mode": "local"
}
```

The health response intentionally omits secrets, raw keys, grant refs, database
paths, and internal configuration.

## Authentication Headers

| Header | Used by | Meaning |
| --- | --- | --- |
| `X-Agent-Key` | Agent routes | Lets an execution agent request or consume authority, and mint subject tokens. |
| `X-Workspace-Key` | Operator routes | Lets workspace/admin authority issue, decide, or configure authority. |
| `X-PEP-Key` | `POST /v1/enforce/delegated` | Authenticates a Policy Enforcement Point (resource server). The trusted PEP workspace is derived only from this key. |
| `X-Subject-Token` | `POST /v1/enforce/delegated` | Optional subject token (raw `vat_...`) presented by a PEP to prove subject identity. |
| `X-Subject-Token-Proof` | `POST /v1/enforce/delegated` | Optional HMAC proof-of-possession over this request's action/resource, required when the presented subject token is PoP-bound. |
| `X-Vinctor-Boundary-Id` | `POST /v1/enforce`, `POST /v1/enforce/delegated` | Optional runtime boundary context for audit. |

Execution agents must not approve their own grant requests, create
auto-approval rules, issue grants directly, or change issuable scope bounds.

## Enforce

`POST /v1/enforce`

Auth: `X-Agent-Key`

Body:

```json
{
  "grant_ref": "grt_...",
  "action": "execute",
  "resource": "ci/test"
}
```

Responses:

- `200` with `decision: permit`
- `403` with `decision: deny`, or `403 forbidden` when the grant_ref is unknown
  or not owned by the requesting agent (the two are indistinguishable — no
  grant_ref is echoed and no exist-vs-belong distinction is made, closing the
  grant-existence oracle)
- `400` for malformed body
- `401` for missing or invalid agent key

## Delegated Enforce

`POST /v1/enforce/delegated`

Auth: `X-PEP-Key`

An on-behalf-of enforce request from a Policy Enforcement Point (resource
server) about a third-party subject (see ADR 0007). The PEP authenticates with
its own key; the trusted PEP workspace is derived only from that authenticated
identity, never from the request body. A caller-asserted `workspace_id`, if
present, must match the trusted PEP workspace.

Body:

```json
{
  "workspace_id": "ws_local",
  "agent_id": "agent_local",
  "grant_ref": "grt_...",
  "action": "execute",
  "resource": "ci/test"
}
```

Optional headers:

- `X-Subject-Token`: a raw subject token (`vat_...`). When present, it must
  agree with the asserted body and the resolved grant; on success the recorded
  audit event sets `identity_proven`. Any mismatch fails closed.
- `X-Subject-Token-Proof`: required when the presented subject token is
  proof-of-possession bound.

Responses:

- `200` with `decision: permit`
- `403` with `decision: deny`, or `403 forbidden` when delegation preconditions
  fail (no trusted PEP workspace, grant not owned by the asserted subject, or a
  required/invalid subject token)
- `400` for malformed body
- `401` for missing or invalid PEP key

## Subject Tokens

`POST /v1/tokens`

Auth: `X-Agent-Key`

Mints a subject token for the authenticated agent. The agent's workspace and id
are taken from `X-Agent-Key`. The grant referenced by `grant_ref` must belong to
that agent and be valid; otherwise the request is rejected.

Body:

```json
{
  "grant_ref": "grt_...",
  "audience": "pep_local",
  "ttl_seconds": 300,
  "action": "execute",
  "resource": "ci/test",
  "pop": false
}
```

`audience` is the target `pep_id`. `ttl_seconds` is optional (defaults apply and
it may not exceed the configured maximum). `action` and `resource` are optional
and both-or-neither; when set they bind the token to that single action and
resource. `pop` is optional and defaults to `false`.

`201` response:

```json
{
  "token": "vat_...",
  "token_id": "vtk_...",
  "expires_at": "2026-06-11T12:05:00+00:00"
}
```

`token` is the raw subject token, returned once and never stored. `token_id` is
the public `vtk_` identifier. When the token was minted with `pop: true`, the
response additionally includes a `pop_secret`, also returned once.

## Grant Requests

`POST /v1/grant-requests`

Auth: `X-Agent-Key`

Body:

```json
{
  "scopes": ["execute:ci/test"],
  "ttl_seconds": 1800,
  "reason": "run CI validation",
  "task_id": "task-ci",
  "session_id": "session-demo",
  "boundary_id": "bnd_...",
  "requester_runtime": "codex",
  "repo": "vinctor-core",
  "worktree": "feature/demo"
}
```

`task_id`, `session_id`, `boundary_id`, `requester_runtime`, `repo`, and
`worktree` are optional metadata fields for demo UX, approval queue context, and
audit correlation. They are not authority by themselves.

The create response includes non-authoritative routing hints:

```json
{
  "request_id": "grq_...",
  "status": "pending",
  "routing_hint": "auto_approval_available",
  "routing_reason": "auto_approval_match"
}
```

Routing hints describe the service's current state. They do not let the agent
choose an approval path.

`GET /v1/grant-requests/{request_id}`

Auth: `X-Agent-Key` or `X-Workspace-Key`

With `X-Agent-Key`, the service returns only requests belonging to that agent in
the same workspace. The response omits operator identity fields such as
`decided_by`.

With `X-Workspace-Key`, the service returns the operator view, including
`routing_hint`, `routing_reason`, and `queue_reason`.

`GET /v1/grant-requests`

Auth: `X-Workspace-Key`

Returns the workspace request queue. Each request includes requester, target,
requested scopes, requested TTL, status, original reason, and current queue
reason.

`POST /v1/grant-requests/{request_id}/auto-approve`

Auth: `X-Workspace-Key`

Evaluates the pending request against active operator-defined auto-approval
rules. A matching rule approves the request and issues a scoped grant. A
non-match leaves the request pending.

`POST /v1/grant-requests/{request_id}/approve`

Auth: `X-Workspace-Key`

Optional body:

```json
{
  "decision_reason": "manual operator review"
}
```

Approves the request and issues a scoped grant through the same service-issued
grant path.

`POST /v1/grant-requests/{request_id}/reject`

Auth: `X-Workspace-Key`

Optional body:

```json
{
  "decision_reason": "not needed for this task"
}
```

Rejects the request without issuing a grant.

## Grants

`POST /v1/grants`

Auth: `X-Workspace-Key`

Issues a scoped grant directly through workspace/admin authority. This route is
not available to `X-Agent-Key`.

Body:

```json
{
  "agent_id": "agent_local",
  "scopes": ["execute:ci/test"],
  "ttl_seconds": 1800
}
```

Precondition: issuable scope bounds must already be configured for the target
agent (`operator bounds set`). If no bounds exist, issuance is rejected with
`403 issuable_bounds_not_found`.

Issuance that exceeds the configured bounds is rejected with
`403 scope_outside_issuable_bounds`. This same 403 mapping applies on the
approval path (`POST /v1/grant-requests/{request_id}/approve`), which issues a
grant through the same service-issued path.

A successful issuance returns `201` with the grant body and an
`audit_event_id`.

`GET /v1/grants`

Auth: `X-Workspace-Key`

Lists grants in the workspace. Supported query parameters:

- `agent_id`
- `status`

Response:

```json
{
  "grants": [
    {
      "grant_id": "grnt_...",
      "grant_ref": "grt_...",
      "workspace_id": "ws_local",
      "agent_id": "agent_local",
      "scopes": ["execute:ci/test"],
      "status": "active",
      "expires_at": "2026-06-11T12:00:00+00:00"
    }
  ]
}
```

`GET /v1/grants/{grant_ref}`

Auth: `X-Workspace-Key`

Looks up a grant in the workspace.

`POST /v1/grants/{grant_ref}/revoke`

Auth: `X-Workspace-Key`

Revokes a grant.

## Audit Events

`GET /v1/audit-events`

Auth: `X-Workspace-Key`

Returns workspace audit events through an explicit output allowlist. Supported
query parameters:

- `limit`: positive integer, default `20`, max `100`
- `event_type`
- `agent_id`
- `grant_ref`
- `boundary_id`
- `request_id`

`request_id` matches both grant request lifecycle events that store the request
id in `grant_ref` and decision events that store it as
`resource=grant_request/{request_id}`.

Response:

```json
{
  "audit_events": [
    {
      "event_id": "evt_...",
      "event_type": "action_denied",
      "decision": "deny",
      "reason": "action_denied",
      "workspace_id": "ws_local",
      "agent_id": "agent_local",
      "grant_id": "grnt_...",
      "grant_ref": "grt_...",
      "action": "execute",
      "resource": "ci/test",
      "scope_attempted": "execute:ci/test",
      "scope_matched": null,
      "boundary_id": "bnd_...",
      "runtime": "codex",
      "boundary_type": "pretooluse",
      "created_at": "2026-06-11T12:00:00+00:00"
    }
  ]
}
```

`GET /v1/audit-events/{event_id}`

Auth: `X-Workspace-Key`

Returns one audit event from the same allowlist.

Audit event HTTP responses must not expose raw audit payloads, raw prompts, raw
tool input, raw commands, raw keys, key hashes, local database paths, or other
service internals.

## Auto-Approval Rules

`POST /v1/auto-approval-rules`

Auth: `X-Workspace-Key`

Creates an operator-defined auto-approval rule.

`GET /v1/auto-approval-rules`

Auth: `X-Workspace-Key`

Lists workspace rules.

`POST /v1/auto-approval-rules/{rule_id}/disable`

Auth: `X-Workspace-Key`

Disables a rule.

## Boundaries

`POST /v1/boundaries`, `GET /v1/boundaries`,
`GET /v1/boundaries/{boundary_id}`,
`POST /v1/boundaries/{boundary_id}/disable`, and
`POST /v1/boundaries/{boundary_id}/enable` are workspace-key-protected local
boundary registry routes.

`POST /v1/boundaries`

Auth: `X-Workspace-Key`

Registers a runtime boundary in the workspace registry.

Body:

```json
{
  "name": "codex-pretooluse",
  "runtime": "codex",
  "boundary_type": "pretooluse",
  "mode": "fail_closed"
}
```

All four fields are required non-empty strings. `mode` must be `"fail_closed"`;
any other value is rejected with `400 invalid_request`. A successful
registration returns `201` with the boundary body (`boundary_id`, `name`,
`runtime`, `boundary_type`, `mode`, `status`).

`GET /v1/boundaries` returns `{"boundaries": [...]}` for the workspace, and
`GET /v1/boundaries/{boundary_id}` returns one boundary body.

This boundary registry is unrelated to the `operator bounds` CLI command, which
configures an agent's issuable scope bounds (see the `POST /v1/grants`
precondition above), not runtime boundaries.

## Reason Codes

Common grant request and auto-approval reasons:

| Reason | Meaning |
| --- | --- |
| `grant_requested` | Agent request was accepted into pending queue. |
| `auto_approval_match` | An active rule would approve the request. |
| `no_matching_rule` | No active rule matched the target agent. |
| `scope_outside_rule` | A rule candidate existed, but requested scopes were outside it. |
| `ttl_exceeds_rule` | A rule candidate existed, but requested TTL was too long. |
| `grant_request_auto_approved` | Workspace-triggered auto-approval issued a grant. |
| `grant_request_approved` | Workspace/admin manually approved the request. |
| `grant_request_rejected` | Workspace/admin rejected the request. |
| `scope_outside_issuable_bounds` | Issuance could not proceed because the request exceeded the agent's issuable scope bounds (direct and approval paths; `403`). |
| `issuable_bounds_not_found` | Issuance could not proceed because no issuable scope bounds are configured for the target agent (direct and approval paths; `403`). |
| `grant_request_not_pending` | A decided request cannot be decided again. |
| `boundary_required` | Enforce denied: the agent is hardened to require a runtime boundary, but none was supplied. |
| `subject_token_required` | Delegated enforce denied: the subject is hardened to require a subject token, but none was presented. |
| `subject_token_invalid` | Delegated enforce denied: the presented subject token failed validation (generic, leak-free; covers invalid, expired, revoked, mismatched, or failed proof-of-possession). |
| `pop_required` | Delegated enforce denied: the subject is hardened to require a proof-of-possession token, but the presented token was not PoP-bound. |

Reason codes are stable enough for local demos and tests, but still part of the
early prototype contract.
